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
"""Tests to verify that our advanced hypothesis strategies are behaving as expected."""
from boto3.dynamodb.types import DYNAMODB_CONTEXT
import hypothesis
import pytest

from dynamodb_encryption_sdk.internal.formatting.deserialize.attribute import deserialize_attribute
from dynamodb_encryption_sdk.internal.formatting.serialize.attribute import serialize_attribute
from dynamodb_encryption_sdk.transform import dict_to_ddb, ddb_to_dict
from .hypothesis_strategies import ddb_items, ddb_negative_numbers, ddb_number, ddb_positive_numbers, VERY_SLOW_SETTINGS

pytestmark = [pytest.mark.functional, pytest.mark.slow, pytest.mark.local, pytest.mark.hypothesis_strategy]


@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_transformable_item(item):
    ddb_json = dict_to_ddb(item)
    serialized = {}
    for key, value in ddb_json.items():
        serialized[key] = serialize_attribute(value)
    deserialized = {}
    for key, value in serialized.items():
        deserialized[key] = deserialize_attribute(value)
    end_result = ddb_to_dict(deserialized)
    assert end_result == item


@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_serializable_item(item):
    ddb_json = dict_to_ddb(item)
    end_result = ddb_to_dict(ddb_json)
    assert end_result == item


@VERY_SLOW_SETTINGS
@hypothesis.given(value=ddb_number)
def test_ddb_number(value):
    DYNAMODB_CONTEXT.create_decimal(value)


@VERY_SLOW_SETTINGS
@hypothesis.given(value=ddb_negative_numbers)
def test_ddb_negative_numbers(value):
    assert value < 0
    DYNAMODB_CONTEXT.create_decimal(value)


@VERY_SLOW_SETTINGS
@hypothesis.given(value=ddb_positive_numbers)
def test_ddb_positive_numbers(value):
    assert value > 0
    DYNAMODB_CONTEXT.create_decimal(value)
