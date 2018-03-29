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
"""Functional tests for material description de/serialization."""
import hypothesis
import pytest

from dynamodb_encryption_sdk.exceptions import InvalidMaterialDescriptionError, InvalidMaterialDescriptionVersionError
from dynamodb_encryption_sdk.internal.formatting.material_description import (
    deserialize as deserialize_material_description, serialize as serialize_material_description
)
from ...functional_test_vector_generators import material_description_test_vectors
from ...hypothesis_strategies import material_descriptions, SLOW_SETTINGS, VERY_SLOW_SETTINGS

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('material_description, serialized', material_description_test_vectors())
def test_serialize_material_description(material_description, serialized):
    serialized_material_description = serialize_material_description(material_description)
    assert serialized_material_description == serialized


@pytest.mark.parametrize('data, expected_type, expected_message', (
    ({'test': 5}, InvalidMaterialDescriptionError, 'Invalid name or value in material description: *'),
    ({5: 'test'}, InvalidMaterialDescriptionError, 'Invalid name or value in material description: *'),
))
def test_serialize_material_description_errors(data, expected_type, expected_message):
    with pytest.raises(expected_type) as exc_info:
        serialize_material_description(data)

    exc_info.match(expected_message)


@pytest.mark.parametrize('material_description, serialized', material_description_test_vectors())
def test_deserialize_material_description(material_description, serialized):
    deserialized_material_description = deserialize_material_description(serialized)
    assert deserialized_material_description == material_description


@pytest.mark.parametrize('data, expected_type, expected_message', (
    # Invalid version
    ({'B': b'\x00\x00\x00\x01'}, InvalidMaterialDescriptionVersionError, r'Invalid material description version: *'),
    # Malformed version
    ({'B': b'\x00\x00\x00'}, InvalidMaterialDescriptionError, r'Malformed material description version'),
    # Invalid attribute type
    ({'S': 'not bytes'}, InvalidMaterialDescriptionError, r'Invalid material description'),
    # Invalid data: not a DDB attribute
    (b'bare bytes', InvalidMaterialDescriptionError, r'Invalid material description'),
    # Partial entry
    (
        {'B': b'\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01A\x00\x00\x00\x01'},
        InvalidMaterialDescriptionError,
        r'Invalid material description'
    )
))
def test_deserialize_material_description_errors(data, expected_type, expected_message):
    with pytest.raises(expected_type) as exc_info:
        deserialize_material_description(data)

    exc_info.match(expected_message)


def _serialize_deserialize_cycle(material_description):
    serialized_material_description = serialize_material_description(material_description)
    deserialized_material_description = deserialize_material_description(serialized_material_description)
    assert deserialized_material_description == material_description


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(material_descriptions)
def test_serialize_deserialize_material_description_slow(material_description):
    _serialize_deserialize_cycle(material_description)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(material_descriptions)
def test_serialize_deserialize_material_description_vslow(material_description):
    _serialize_deserialize_cycle(material_description)
