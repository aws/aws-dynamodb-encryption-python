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
"""Helper tools for collecting test vectors for use in functional tests."""
import base64
import codecs
from decimal import Decimal
import json
import os

from boto3.dynamodb.types import Binary

from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.structures import AttributeActions

_ATTRIBUTE_TEST_VECTOR_FILE_TEMPLATE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'vectors',
    '{mode}_attribute.json'
)
_MATERIAL_DESCRIPTION_TEST_VECTORS_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'vectors',
    'material_description.json'
)
_STRING_TO_SIGN_TEST_VECTORS_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'vectors',
    'string_to_sign.json'
)


def decode_value(value, transform_binary=False):  # noqa: C901
    def _decode_string(_value):
        return _value

    def _decode_number(_value):
        return '{0:f}'.format(Decimal(_value))

    def _decode_binary(_value):
        raw = base64.b64decode(_value)
        if transform_binary:
            return Binary(raw)
        return raw

    def _binary_sort_key(x):
        if transform_binary:
            return x.value
        return x

    def _passthrough_sort_key(x):
        return x

    def _decode_set(_value, member_decode, key_func=_passthrough_sort_key):
        decoded_members = []
        for member in _value:
            decoded_members.append(member_decode(member))
        return sorted(decoded_members, key=key_func)

    def _decode_binary_set(_value):
        return _decode_set(_value, _decode_binary, _binary_sort_key)

    def _decode_string_set(_value):
        return _decode_set(_value, _decode_string)

    def _decode_number_set(_value):
        return _decode_set(_value, _decode_number)

    def _decode_list(_value):
        decoded_members = []
        for member in _value:
            decoded_members.append(_decode_complex_value(member))
        return decoded_members

    def _decode_map(_value):
        decoded_value = {}
        for member_key, member_value in _value.items():
            decoded_value[member_key] = _decode_complex_value(member_value)
        return decoded_value

    _decode_mapping = {
        'S': _decode_string,
        'B': _decode_binary,
        'SS': _decode_string_set,
        'BS': _decode_binary_set,
        'L': _decode_list,
        'M': _decode_map,
        'N': _decode_number,
        'NS': _decode_number_set
    }

    def _decode_complex_value(_value):
        key, item = list(_value.items())[0]
        transform = _decode_mapping.get(key, None)
        if transform is None:
            return {key: item}
        return {key: transform(item)}

    return _decode_complex_value(value)


def attribute_test_vectors(mode):
    filepath = _ATTRIBUTE_TEST_VECTOR_FILE_TEMPLATE.format(mode=mode)
    with open(filepath) as f:
        vectors = json.load(f)
    for vector in vectors:
        yield (
            decode_value(vector['attribute']),
            base64.b64decode(codecs.encode(vector['serialized'], 'utf-8'))
        )


def material_description_test_vectors():
    with open(_MATERIAL_DESCRIPTION_TEST_VECTORS_FILE) as f:
        vectors = json.load(f)
    for vector in vectors:
        yield (
            vector['material_description'],
            decode_value({'B': codecs.encode(vector['serialized'], 'utf-8')})
        )


ACTION_MAP = {
    'encrypt': CryptoAction.ENCRYPT_AND_SIGN,
    'sign': CryptoAction.SIGN_ONLY,
    'nothing': CryptoAction.DO_NOTHING
}


def string_to_sign_test_vectors():
    with open(_STRING_TO_SIGN_TEST_VECTORS_FILE) as f:
        vectors = json.load(f)
    for vector in vectors:
        item = {
            key: decode_value(value['value'])
            for key, value in vector['item'].items()
        }
        bare_actions = {key: ACTION_MAP[value['action']] for key, value in vector['item'].items()}
        attribute_actions = AttributeActions(
            default_action=CryptoAction.DO_NOTHING,
            attribute_actions=bare_actions
        )
        yield (
            item,
            vector['table'],
            attribute_actions,
            base64.b64decode(codecs.encode(vector['string_to_sign'], 'utf-8'))
        )
