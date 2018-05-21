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
"""Functional tests for ``dynamodb_encryption_sdk.structures``."""
import boto3
import pytest

from dynamodb_encryption_sdk.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.structures import AttributeActions, TableIndex, TableInfo
from .functional_test_utils import (
    example_table, table_with_global_seconary_indexes, table_with_local_seconary_indexes, TEST_TABLE_NAME
)

pytestmark = [pytest.mark.functional, pytest.mark.local]


# TODO: There is a way to parameterize fixtures, but the existing docs on that are very unclear.
# This will get us what we need for now, but we should come back to this to clean this up later.
def test_tableinfo_refresh_indexes_no_secondary_indexes(example_table):
    client = boto3.client('dynamodb', region_name='us-west-2')
    table = TableInfo(name=TEST_TABLE_NAME)

    table.refresh_indexed_attributes(client)


def test_tableinfo_refresh_indexes_with_gsis(table_with_global_seconary_indexes):
    client = boto3.client('dynamodb', region_name='us-west-2')
    table = TableInfo(name=TEST_TABLE_NAME)

    table.refresh_indexed_attributes(client)


def test_tableinfo_refresh_indexes_with_lsis(table_with_local_seconary_indexes):
    client = boto3.client('dynamodb', region_name='us-west-2')
    table = TableInfo(name=TEST_TABLE_NAME)

    table.refresh_indexed_attributes(client)


@pytest.mark.parametrize('kwargs, expected_attributes', (
    (dict(partition='partition_name'), set(['partition_name'])),
    (dict(partition='partition_name', sort='sort_name'), set(['partition_name', 'sort_name']))
))
def test_tableindex_attributes(kwargs, expected_attributes):
    index = TableIndex(**kwargs)
    assert index.attributes == expected_attributes


@pytest.mark.parametrize('key_schema, expected_kwargs', (
    (
        [
            {
                'KeyType': 'HASH',
                'AttributeName': 'partition_name'
            }
        ],
        dict(partition='partition_name')
    ),
    (
        [
            {
                'KeyType': 'HASH',
                'AttributeName': 'partition_name'
            },
            {
                'KeyType': 'RANGE',
                'AttributeName': 'sort_name'
            }
        ],
        dict(partition='partition_name', sort='sort_name')
    )
))
def test_tableindex_from_key_schema(key_schema, expected_kwargs):
    index = TableIndex.from_key_schema(key_schema)
    expected_index = TableIndex(**expected_kwargs)

    assert index == expected_index


@pytest.mark.parametrize('default, overrides, expected_result', (
    (CryptoAction.ENCRYPT_AND_SIGN, {}, CryptoAction.SIGN_ONLY),
    (CryptoAction.SIGN_ONLY, {}, CryptoAction.SIGN_ONLY),
    (CryptoAction.DO_NOTHING, {}, CryptoAction.DO_NOTHING),
    (CryptoAction.ENCRYPT_AND_SIGN, {'indexed_attribute': CryptoAction.SIGN_ONLY}, CryptoAction.SIGN_ONLY),
    (CryptoAction.ENCRYPT_AND_SIGN, {'indexed_attribute': CryptoAction.DO_NOTHING}, CryptoAction.DO_NOTHING),
    (CryptoAction.SIGN_ONLY, {'indexed_attribute': CryptoAction.SIGN_ONLY}, CryptoAction.SIGN_ONLY),
    (CryptoAction.SIGN_ONLY, {'indexed_attribute': CryptoAction.DO_NOTHING}, CryptoAction.DO_NOTHING),
    (CryptoAction.DO_NOTHING, {'indexed_attribute': CryptoAction.SIGN_ONLY}, CryptoAction.SIGN_ONLY),
    (CryptoAction.DO_NOTHING, {'indexed_attribute': CryptoAction.DO_NOTHING}, CryptoAction.DO_NOTHING)
))
def test_attribute_actions_index_override(default, overrides, expected_result):
    test = AttributeActions(default_action=default, attribute_actions=overrides)
    test.set_index_keys('indexed_attribute')

    assert test.action('indexed_attribute') is expected_result


@pytest.mark.parametrize('default', CryptoAction)
def test_attribute_actions_index_override_fail(default):
    test = AttributeActions(
        default_action=default,
        attribute_actions={'indexed_attribute': CryptoAction.ENCRYPT_AND_SIGN}
    )

    with pytest.raises(InvalidArgumentError) as excinfo:
        test.set_index_keys('indexed_attribute')

    excinfo.match(r'Cannot overwrite a previously requested action on indexed attribute: *')
