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
"""Helper tools for use in tests."""
from __future__ import division

from collections import defaultdict
import copy
from decimal import Decimal
import itertools

import boto3
from boto3.dynamodb.types import Binary
from moto import mock_dynamodb2
import pytest

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk.identifiers import ItemAction
from dynamodb_encryption_sdk.internal.identifiers import ReservedAttributes
from dynamodb_encryption_sdk.material_providers.static import StaticCryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials
from dynamodb_encryption_sdk.structures import AttributeActions

_DELEGATED_KEY_CACHE = defaultdict(lambda: defaultdict(dict))
TEST_TABLE_NAME = 'my_table'
TEST_INDEX = {
    'partition_attribute': {
        'type': 'S',
        'value': 'test_value'
    },
    'sort_attribute': {
        'type': 'N',
        'value': Decimal('99.233')
    }
}
TEST_KEY = {name: value['value'] for name, value in TEST_INDEX.items()}
TEST_BATCH_INDEXES = [
    {
        'partition_attribute': {
            'type': 'S',
            'value': 'test_value'
        },
        'sort_attribute': {
            'type': 'N',
            'value': Decimal('99.233')
        }
    },
    {
        'partition_attribute': {
            'type': 'S',
            'value': 'test_value'
        },
        'sort_attribute': {
            'type': 'N',
            'value': Decimal('92986745')
        }
    },
    {
        'partition_attribute': {
            'type': 'S',
            'value': 'test_value'
        },
        'sort_attribute': {
            'type': 'N',
            'value': Decimal('2231.0001')
        }
    },
    {
        'partition_attribute': {
            'type': 'S',
            'value': 'another_test_value'
        },
        'sort_attribute': {
            'type': 'N',
            'value': Decimal('732342')
        }
    }
]
TEST_BATCH_KEYS = [
    {name: value['value'] for name, value in key.items()}
    for key in TEST_BATCH_INDEXES
]


@pytest.fixture
def example_table():
    mock_dynamodb2().start()
    ddb = boto3.client('dynamodb', region_name='us-west-2')
    ddb.create_table(
        TableName=TEST_TABLE_NAME,
        KeySchema=[
            {
                'AttributeName': 'partition_attribute',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'sort_attribute',
                'KeyType': 'RANGE'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': name,
                'AttributeType': value['type']
            }
            for name, value in TEST_INDEX.items()
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 100,
            'WriteCapacityUnits': 100
        }
    )
    yield
    ddb.delete_table(TableName=TEST_TABLE_NAME)
    mock_dynamodb2().stop()


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
            metafunc.parametrize(name, _all_possible_cmps(algorithm_generator))


_ACTIONS = {
    'hypothesis_actions': (
        pytest.param(AttributeActions(default_action=ItemAction.ENCRYPT_AND_SIGN), id='encrypt all'),
        pytest.param(AttributeActions(default_action=ItemAction.SIGN_ONLY), id='sign only all'),
        pytest.param(AttributeActions(default_action=ItemAction.DO_NOTHING), id='do nothing'),
    )
}
_ACTIONS['parametrized_actions'] = _ACTIONS['hypothesis_actions'] + (
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


def set_parametrized_actions(metafunc):
    """Set parametrized values for attribute actions."""
    for name, actions in _ACTIONS.items():
        if name in metafunc.fixturenames:
            metafunc.parametrize(name, actions)


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
    if attribute_actions.take_no_actions:
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


def _matching_key(actual_item, expected):
    expected_item = [
        i for i in expected
        if i['partition_attribute'] == actual_item['partition_attribute'] and
        i['sort_attribute'] == actual_item['sort_attribute']
    ]
    assert len(expected_item) == 1
    return expected_item[0]


def _nop_transformer(item):
    return item


def assert_equal_lists_of_items(actual, expected, transformer=_nop_transformer):
    assert len(actual) == len(expected)

    for actual_item in actual:
        expected_item = _matching_key(actual_item, expected)
        assert transformer(actual_item) == transformer(expected_item)


def check_many_encrypted_items(actual, expected, attribute_actions, transformer=_nop_transformer):
    assert len(actual) == len(expected)

    for actual_item in actual:
        expected_item = _matching_key(actual_item, expected)
        check_encrypted_item(
            plaintext_item=transformer(expected_item),
            ciphertext_item=transformer(actual_item),
            attribute_actions=attribute_actions
        )


def cycle_batch_item_check(
        raw,
        encrypted,
        initial_actions,
        initial_item,
        write_transformer=_nop_transformer,
        read_transformer=_nop_transformer
):
    """Check that cycling (plaintext->encrypted->decrypted) item batch has the expected results."""
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    items = []
    for key in TEST_BATCH_KEYS:
        _item = initial_item.copy()
        _item.update(key)
        items.append(write_transformer(_item))

    _put_result = encrypted.batch_write_item(  # noqa
        RequestItems={
            TEST_TABLE_NAME: [
                {'PutRequest': {'Item': _item}}
                for _item in items
            ]
        }
    )

    ddb_keys = [write_transformer(key) for key in TEST_BATCH_KEYS]
    encrypted_result = raw.batch_get_item(
        RequestItems={
            TEST_TABLE_NAME: {
                'Keys': ddb_keys
            }
        }
    )
    check_many_encrypted_items(
        actual=encrypted_result['Responses'][TEST_TABLE_NAME],
        expected=items,
        attribute_actions=check_attribute_actions,
        transformer=read_transformer
    )

    decrypted_result = encrypted.batch_get_item(
        RequestItems={
            TEST_TABLE_NAME: {
                'Keys': ddb_keys
            }
        }
    )
    assert_equal_lists_of_items(
        actual=decrypted_result['Responses'][TEST_TABLE_NAME],
        expected=items,
        transformer=read_transformer
    )

    _delete_result = encrypted.batch_write_item(  # noqa
        RequestItems={
            TEST_TABLE_NAME: [
                {'DeleteRequest': {'Key': _key}}
                for _key in ddb_keys
            ]
        }
    )

    del check_attribute_actions
    del items


def cycle_item_check(plaintext_item, crypto_config):
    """Check that cycling (plaintext->encrypted->decrypted) an item has the expected results."""
    ciphertext_item = encrypt_python_item(plaintext_item, crypto_config)

    check_encrypted_item(plaintext_item, ciphertext_item, crypto_config.attribute_actions)

    cycled_item = decrypt_python_item(ciphertext_item, crypto_config)

    assert cycled_item == plaintext_item
    del ciphertext_item
    del cycled_item
