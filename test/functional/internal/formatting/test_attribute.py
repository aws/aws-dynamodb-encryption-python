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
"""Functional tests for attribute de/serialization."""
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
import hypothesis
import pytest

from dynamodb_encryption_sdk.exceptions import DeserializationError, SerializationError
from dynamodb_encryption_sdk.internal.formatting.deserialize.attribute import deserialize_attribute
from dynamodb_encryption_sdk.internal.formatting.serialize.attribute import serialize_attribute
from dynamodb_encryption_sdk.transform import ddb_to_dict, dict_to_ddb
from ...functional_test_vector_generators import attribute_test_vectors
from ...hypothesis_strategies import ddb_attribute_values, ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('attribute, serialized', attribute_test_vectors('serialize'))
def test_serialize_attribute(attribute, serialized):
    serialized_attribute = serialize_attribute(attribute)
    assert serialized_attribute == serialized


@pytest.mark.parametrize('attribute, expected_type, expected_message', (
    ({'_': None}, SerializationError, r'Unsupported DynamoDB data type: *'),
    ({}, SerializationError, r'cannot serialize attribute: incorrect number of members *'),
    ({'a': None, 'b': None}, SerializationError, r'cannot serialize attribute: incorrect number of members *'),
    (None, TypeError, r'Invalid attribute type *')
))
def test_serialize_attribute_errors(attribute, expected_type, expected_message):
    with pytest.raises(expected_type) as excinfo:
        serialize_attribute(attribute)

    excinfo.match(expected_message)


@pytest.mark.parametrize('attribute, serialized', attribute_test_vectors('deserialize'))
def test_deserialize_attribute(attribute, serialized):
    deserialized_attribute = deserialize_attribute(serialized)
    assert deserialized_attribute == attribute


@pytest.mark.parametrize('data, expected_type, expected_message', (
    (b'', DeserializationError, r'Empty serialized attribute data'),
    (b'_', DeserializationError, r'Malformed serialized data'),
    (b'\x00_', DeserializationError, r'Unsupported tag: *'),
    (b'__', DeserializationError, r'Invalid tag: reserved byte is not null'),
    (b'\x00M\x00\x00\x00\x01\x00\x00', DeserializationError, r'Malformed serialized map: *')
))
def test_deserialize_attribute_errors(data, expected_type, expected_message):
    with pytest.raises(expected_type) as exc_info:
        deserialize_attribute(data)

    exc_info.match(expected_message)


def _serialize_deserialize_cycle(attribute):
    raw_attribute = TypeSerializer().serialize(attribute)
    serialized_attribute = serialize_attribute(raw_attribute)
    cycled_attribute = deserialize_attribute(serialized_attribute)
    deserialized_attribute = TypeDeserializer().deserialize(cycled_attribute)
    assert deserialized_attribute == attribute


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(ddb_attribute_values)
def test_serialize_deserialize_attribute_slow(attribute):
    _serialize_deserialize_cycle(attribute)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(ddb_attribute_values)
def test_serialize_deserialize_attribute_vslow(attribute):
    _serialize_deserialize_cycle(attribute)


def _ddb_dict_ddb_transform_cycle(item):
    ddb_item = dict_to_ddb(item)
    cycled_item = ddb_to_dict(ddb_item)
    assert cycled_item == item


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(ddb_items)
def test_dict_to_ddb_and_back_slow(item):
    _ddb_dict_ddb_transform_cycle(item)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(ddb_items)
def test_dict_to_ddb_and_back_vslow(item):
    _ddb_dict_ddb_transform_cycle(item)
