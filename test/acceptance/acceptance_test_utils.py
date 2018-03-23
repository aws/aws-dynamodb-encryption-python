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
import base64
from collections import defaultdict
import json
import os
import sys
sys.path.append(os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'functional'
))

import pytest
from six.moves.urllib.parse import urlparse


from dynamodb_encryption_sdk.material_providers.static import StaticCryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials
from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.identifiers import EncryptionKeyTypes, ItemAction, KeyEncodingType
from dynamodb_encryption_sdk.structures import AttributeActions

import functional_test_vector_generators

_ENCRYPTED_ITEM_VECTORS_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'vectors',
    'encrypted_item'
)
_SCENARIO_FILE = os.path.join(_ENCRYPTED_ITEM_VECTORS_DIR, 'scenarios.json')


def _filename_from_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme != 'file':
        raise ValueError('Unsupported URI scheme: "{}"'.format(parsed.scheme))
    relative_path = [parsed.netloc]
    for part in parsed.path.split('/'):
        if part:
            relative_path.append(part)
    return os.path.join(_ENCRYPTED_ITEM_VECTORS_DIR, *relative_path)


def _action(name):
    return functional_test_vector_generators.ACTION_MAP[name.lower()]


def _decode_item(item):
    for name, attribute in item.items():
        item[name] = functional_test_vector_generators.decode_value(attribute)


def _build_plaintext_items(plaintext_file, version):
    """"""
    with open(plaintext_file) as f:
        plaintext_data = json.load(f)

    actions = {}
    for name, description in plaintext_data['actions'].items():
        default_action = _action(description['default'])
        attribute_actions = {
            attribute_name: _action(attribute_action)
            for attribute_name, attribute_action
            in description.get('override', {}).items()
        }
        actions[name.lower()] = AttributeActions(
            default_action=default_action,
            attribute_actions=attribute_actions
        )

    tables = defaultdict(list)
    for table_name, table_data in plaintext_data['items'].items():
        table_items = []
        for item in table_data['items']:
            item_actions = actions[item['action']].copy()
            item_actions.set_index_keys(*table_data['index'].values())
            attributes = item['attributes'].copy()
            if not item.get('exact', False):
                for group in plaintext_data['versions'].get(table_name, {}).get(version, []):
                    attributes.update(plaintext_data['attributes'][group])
            _decode_item(attributes)
            table_items.append(dict(
                item=attributes,
                action=item_actions
            ))

        tables[table_name] = dict(
            index=table_data['index'],
            items=table_items
        )

    return tables


def _load_ciphertext_items(ciphertext_file):
    with open(ciphertext_file) as f:
        ciphertexts = json.load(f)

    for _table, items in ciphertexts.items():
        for item in items:
            _decode_item(item)

    return ciphertexts


def _load_keys(keys_file):
    with open(keys_file) as f:
        return json.load(f)


_KEY_TYPE = {
    'SYMMETRIC': EncryptionKeyTypes.SYMMETRIC,
    'PUBLIC': EncryptionKeyTypes.PUBLIC,
    'PRIVATE': EncryptionKeyTypes.PRIVATE
}
_KEY_ENCODING = {
    'RAW': KeyEncodingType.RAW,
    'DER': KeyEncodingType.DER
}


def _load_key(key):
    key_material = base64.b64decode(key['material'])
    key_type = _KEY_TYPE[key['type'].upper()]
    key_encoding = _KEY_ENCODING[key['encoding'].upper()]
    return JceNameLocalDelegatedKey(
        key=key_material,
        algorithm=key['algorithm'],
        key_type=key_type,
        key_encoding=key_encoding
    )


def _load_signing_key(key):
    if key['type'].upper() == 'RSA':
        key['type'] = 'RSA'
    return _load_key(key)


def _build_static_cmp(decrypt_key, verify_key):
    decryption_key = _load_key(decrypt_key)
    verification_key = _load_signing_key(verify_key)
    decryption_materials = RawDecryptionMaterials(
        decryption_key=decryption_key,
        verification_key=verification_key
    )
    return StaticCryptographicMaterialsProvider(decryption_materials=decryption_materials)


def _build_wrapped_cmp(decrypt_key, verify_key):
    unwrapping_key = _load_key(decrypt_key)
    signing_key = _load_signing_key(verify_key)
    return WrappedCryptographicMaterialsProvider(
        signing_key=signing_key,
        unwrapping_key=unwrapping_key
    )


_CMP_TYPE_MAP = {
    'STATIC': _build_static_cmp,
    'WRAPPED': _build_wrapped_cmp
}


def _build_cmp(provider_type, decrypt_key, verify_key):
    try:
        cmp_builder = _CMP_TYPE_MAP[provider_type.upper()]
    except KeyError:
        raise ValueError('Unsupported cryptographic materials provider type: "{}"'.format(provider_type))
    return cmp_builder(decrypt_key, verify_key)


def _index(item, keys):
    return {key: item[key] for key in keys}


def _expand_items(ciphertext_items, plaintext_items):
    for table_name, table_items in ciphertext_items.items():
        table_index = plaintext_items[table_name]['index']
        for ciphertext_item in table_items:
            ct_index = _index(ciphertext_item, plaintext_items[table_name]['index'].values())
            pt_items = [
                item for item
                in plaintext_items[table_name]['items']
                if ct_index == _index(item['item'], plaintext_items[table_name]['index'].values())
            ]
            if not pt_items:
                continue

            if len(pt_items) > 1:
                raise Exception('TODO: Ciphertext matches multiple plaintext items: "{}"'.format(ct_index))

            pt_item = pt_items[0]
            yield table_name, table_index, ciphertext_item, pt_item['item'], pt_item['action']


def load_scenarios():
    with open(_SCENARIO_FILE) as f:
        scenarios = json.load(f)
    keys_file = _filename_from_uri(scenarios['keys'])
    keys = _load_keys(keys_file)
    for scenario in scenarios['scenarios']:
        plaintext_file = _filename_from_uri(scenario['plaintext'])
        ciphertext_file = _filename_from_uri(scenario['ciphertext'])
        plaintext_items = _build_plaintext_items(plaintext_file, scenario['version'])
        ciphertext_items = _load_ciphertext_items(ciphertext_file)
        materials_provider = _build_cmp(
            provider_type=scenario['provider'],
            decrypt_key=keys[scenario['keys']['decrypt']],
            verify_key=keys[scenario['keys']['verify']]
        )
        items = _expand_items(ciphertext_items, plaintext_items)
        for table_name, table_index, ciphertext_item, plaintext_item, attribute_actions in items:
            item_index = _index(ciphertext_item, table_index.values())
            yield pytest.param(
                materials_provider,
                table_name,
                table_index,
                ciphertext_item,
                plaintext_item,
                attribute_actions,
                id='{version}-{provider}-{decrypt_key}-{verify_key}-{table}-{index}'.format(
                    version=scenario['version'],
                    provider=scenario['provider'],
                    decrypt_key=scenario['keys']['decrypt'],
                    verify_key=scenario['keys']['verify'],
                    table=table_name,
                    index=str(item_index)
                )
            )
