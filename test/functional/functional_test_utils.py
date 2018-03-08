# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
from __future__ import division
import copy
from collections import defaultdict
from decimal import Decimal
import itertools

from boto3.dynamodb.types import Binary
import pytest

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk.identifiers import ItemAction
from dynamodb_encryption_sdk.internal.identifiers import ReservedAttributes
from dynamodb_encryption_sdk.material_providers.static import StaticCryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext

_DELEGATED_KEY_CACHE = defaultdict(lambda: defaultdict(dict))


def _get_from_cache(dk_class, algorithm, key_length):
    """Don't generate new keys every time. All we care about is that they are valid keys, not that they are unique."""
    try:
        return _DELEGATED_KEY_CACHE[dk_class][algorithm][key_length]
    except KeyError:
        key = dk_class.generate(algorithm, key_length)
        _DELEGATED_KEY_CACHE[dk_class][algorithm][key_length] = key
        return key


def build_static_jce_cmp(encryption_algorithm, encryption_key_length, signing_algorithm, signing_key_length):
    """Build a StaticCryptographicMaterialsProvider using ephemeral JceNameLocalDelegatedKeys as specified."""
    encryption_key = _get_from_cache(JceNameLocalDelegatedKey, encryption_algorithm, encryption_key_length)
    authentication_key = _get_from_cache(JceNameLocalDelegatedKey, signing_algorithm, signing_key_length)
    encryption_materials = RawEncryptionMaterials(
        signing_key=authentication_key,
        encryption_key=encryption_key
    )
    decryption_materials = RawDecryptionMaterials(
        verification_key=authentication_key,
        decryption_key=encryption_key
    )
    return StaticCryptographicMaterialsProvider(
        encryption_materials=encryption_materials,
        decryption_materials=decryption_materials
    )


def _build_wrapped_jce_cmp(wrapping_algorithm, wrapping_key_length, signing_algorithm, signing_key_length):
    """Build a WrappedCryptographicMaterialsProvider using ephemeral JceNameLocalDelegatedKeys as specified."""
    wrapping_key = _get_from_cache(JceNameLocalDelegatedKey, wrapping_algorithm, wrapping_key_length)
    signing_key = _get_from_cache(JceNameLocalDelegatedKey, signing_algorithm, signing_key_length)
    return WrappedCryptographicMaterialsProvider(
        wrapping_key=wrapping_key,
        unwrapping_key=wrapping_key,
        signing_key=signing_key
    )


def _all_encryption():
    """All encryption configurations to test in slow tests."""
    return itertools.chain(
        itertools.product(('AES',), (128, 256)),
        itertools.product(('RSA',), (1024, 2048, 4096))
    )


def _all_authentication():
    """All authentication configurations to test in slow tests."""
    return itertools.chain(
        itertools.product(
            ('HmacSHA224', 'HmacSHA256', 'HmacSHA384', 'HmacSHA512'),
            (128, 256)
        ),
        itertools.product(
            ('SHA224withRSA', 'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA'),
            (1024, 2048, 4096)
        )
    )


def _all_algorithm_pairs():
    """All algorithm pairs (encryption + authentication) to test in slow tests."""
    for encryption_pair, signing_pair in itertools.product(_all_encryption(), _all_authentication()):
        yield encryption_pair + signing_pair


def _some_algorithm_pairs():
    """Cherry-picked set of algorithm pairs (encryption + authentication) to test in fast tests."""
    return (
        ('AES', 256, 'HmacSHA256', 256),
        ('AES', 256, 'SHA256withRSA', 4096),
        ('RSA', 4096, 'SHA256withRSA', 4096)
    )


_cmp_builders = {
    'static': build_static_jce_cmp,
    'wrapped': _build_wrapped_jce_cmp
}


def _all_possible_cmps(algorithm_generator):
    """Generate all possible cryptographic materials providers based on the supplied generator."""
    # The AES combinations do the same thing, but this makes sure that the AESWrap name works as expected.
    yield _build_wrapped_jce_cmp('AESWrap', 32, 'HmacSHA256', 32)

    for builder_info, args in itertools.product(_cmp_builders.items(), algorithm_generator()):
        builder_type, builder_func = builder_info
        encryption_algorithm, encryption_key_length, signing_algorithm, signing_key_length = args

        if builder_type == 'static' and encryption_algorithm != 'AES':
            # Only AES keys are allowed to be used with static materials
            continue

        id_string = '{enc_algorithm}/{enc_key_length} {builder_type} {sig_algorithm}/{sig_key_length}'.format(
            enc_algorithm=encryption_algorithm,
            enc_key_length=encryption_key_length,
            builder_type=builder_type,
            sig_algorithm=signing_algorithm,
            sig_key_length=signing_key_length
        )

        if encryption_algorithm == 'AES':
            encryption_key_length //= 8

        yield pytest.param(
            builder_func(
                encryption_algorithm,
                encryption_key_length,
                signing_algorithm,
                signing_key_length
            ),
            id=id_string
        )


def set_parametrized_cmp(metafunc):
    """Set paramatrized values for cryptographic materials providers."""
    for name, algorithm_generator in (('all_the_cmps', _all_algorithm_pairs), ('some_cmps', _some_algorithm_pairs)):
        if name in metafunc.fixturenames:
            metafunc.parametrize(name, _all_possible_cmps(algorithm_generator), scope='module')


def set_parametrized_actions(metafunc):
    """Set parametrized values for attribute actions"""
    if 'parametrized_actions' in metafunc.fixturenames:
        metafunc.parametrize(
            'parametrized_actions',
            (
                pytest.param(AttributeActions(default_action=ItemAction.ENCRYPT_AND_SIGN), id='encrypt all'),
                pytest.param(AttributeActions(default_action=ItemAction.SIGN_ONLY), id='sign only all'),
                pytest.param(AttributeActions(default_action=ItemAction.DO_NOTHING), id='do nothing'),
                pytest.param(
                    AttributeActions(
                        default_action=ItemAction.ENCRYPT_AND_SIGN,
                        attribute_actions={
                            'number_set': ItemAction.SIGN_ONLY,
                            'string_set': ItemAction.SIGN_ONLY,
                            'binary_set': ItemAction.SIGN_ONLY
                        }
                    ),
                    id='sign sets, encrypt everything else'
                ),
                pytest.param(
                    AttributeActions(
                        default_action=ItemAction.ENCRYPT_AND_SIGN,
                        attribute_actions={
                            'number_set': ItemAction.DO_NOTHING,
                            'string_set': ItemAction.DO_NOTHING,
                            'binary_set': ItemAction.DO_NOTHING
                        }
                    ),
                    id='ignore sets, encrypt everything else'
                ),
                pytest.param(
                    AttributeActions(
                        default_action=ItemAction.DO_NOTHING,
                        attribute_actions={'map': ItemAction.ENCRYPT_AND_SIGN}
                    ),
                    id='encrypt map, ignore everything else'
                ),
                pytest.param(
                    AttributeActions(
                        default_action=ItemAction.SIGN_ONLY,
                        attribute_actions={
                            'number_set': ItemAction.DO_NOTHING,
                            'string_set': ItemAction.DO_NOTHING,
                            'binary_set': ItemAction.DO_NOTHING,
                            'map': ItemAction.ENCRYPT_AND_SIGN
                        }
                    ),
                    id='ignore sets, encrypt map, sign everything else'
                )
            )
        )


def set_parametrized_item(metafunc):
    """Set parametrized values for items to cycle."""
    if 'parametrized_item' in metafunc.fixturenames:
        metafunc.parametrize(
            'parametrized_item',
            (
                pytest.param(diverse_item(), id='diverse item'),
            )
        )


def diverse_item():
    base_item = {
        'int': 5,
        'decimal': Decimal('123.456'),
        'string': 'this is a string',
        'binary': b'this is a bytestring! \x01',
        'number_set': set([5, 4, 3]),
        'string_set': set(['abc', 'def', 'geh']),
        'binary_set': set([b'\x00\x00\x00', b'\x00\x01\x00', b'\x00\x00\x02'])
    }
    base_item['list'] = [copy.copy(i) for i in base_item.values()]
    base_item['map'] = copy.deepcopy(base_item)
    return copy.deepcopy(base_item)


_reserved_attributes = set([attr.value for attr in ReservedAttributes])


def check_encrypted_item(plaintext_item, ciphertext_item, attribute_actions):
    # Verify that all expected attributes are present
    ciphertext_attributes = set(ciphertext_item.keys())
    plaintext_attributes = set(plaintext_item.keys())
    if crypto_config.attribute_actions.take_no_actions:
        assert ciphertext_attributes == plaintext_attributes
    else:
        assert ciphertext_attributes == plaintext_attributes.union(_reserved_attributes)

    for name, value in ciphertext_item.items():
        # Skip the attributes we add
        if name in _reserved_attributes:
            continue

        # If the attribute should have been encrypted, verify that it is Binary and different from the original
        if attribute_actions.action(name) is ItemAction.ENCRYPT_AND_SIGN:
            assert isinstance(value, Binary)
            assert value != plaintext_item[name]
        # Otherwise, verify that it is the same as the original
        else:
            assert value == plaintext_item[name]


def cycle_item_check(plaintext_item, crypto_config):
    """Common logic for cycled item (plaintext->encrypted->decrypted) tests: used by many test suites."""
    ciphertext_item = encrypt_python_item(plaintext_item, crypto_config)

    check_encrypted_item(plaintext_item, ciphertext_item, crypto_config.attribute_actions)

    cycled_item = decrypt_python_item(ciphertext_item, crypto_config)
    assert cycled_item == plaintext_item
