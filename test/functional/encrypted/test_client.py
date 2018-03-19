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
""""""
import boto3
import hypothesis
import pytest

from ..functional_test_utils import (
    check_encrypted_item, example_table, set_parametrized_actions, set_parametrized_cmp, set_parametrized_item,
    TEST_BATCH_KEYS, TEST_KEY, TEST_TABLE_NAME
)
from ..hypothesis_strategies import ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS
from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk.internal.formatting.transform import ddb_to_dict, dict_to_ddb

pytestmark = [pytest.mark.functional, pytest.mark.local]


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


def _client_cycle_single_item_check(materials_provider, initial_actions, initial_item):
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    item = initial_item.copy()
    item.update(TEST_KEY)
    ddb_item = dict_to_ddb(item)
    ddb_key = dict_to_ddb(TEST_KEY)

    client = boto3.client('dynamodb', region_name='us-west-2')
    e_client = EncryptedClient(
        client=client,
        materials_provider=materials_provider,
        attribute_actions=initial_actions
    )

    _put_result = e_client.put_item(
        TableName=TEST_TABLE_NAME,
        Item=ddb_item
    )

    encrypted_result = client.get_item(
        TableName=TEST_TABLE_NAME,
        Key=ddb_key
    )
    check_encrypted_item(item, ddb_to_dict(encrypted_result['Item']), check_attribute_actions)

    decrypted_result = e_client.get_item(
        TableName=TEST_TABLE_NAME,
        Key=ddb_key
    )
    assert ddb_to_dict(decrypted_result['Item']) == item

    e_client.delete_item(
        TableName=TEST_TABLE_NAME,
        Key=ddb_key
    )
    del item
    del check_attribute_actions


def _matching_key(actual_item, expected):
        expected_item = [
            i for i in expected
            if i['partition_attribute'] == actual_item['partition_attribute']
            and i['sort_attribute'] == actual_item['sort_attribute']
        ]
        assert len(expected_item) == 1
        return expected_item[0]


def _assert_equal_lists_of_items(actual, expected):
    assert len(actual) == len(expected)

    for actual_item in actual:
        expected_item = _matching_key(actual_item, expected)
        assert ddb_to_dict(actual_item) == ddb_to_dict(expected_item)


def _check_encrypted_items(actual, expected, attribute_actions):
    assert len(actual) == len(expected)

    for actual_item in actual:
        expected_item = _matching_key(actual_item, expected)
        check_encrypted_item(
            plaintext_item=ddb_to_dict(expected_item),
            ciphertext_item=ddb_to_dict(actual_item),
            attribute_actions=attribute_actions
        )


def _client_cycle_batch_items_check(materials_provider, initial_actions, initial_item):
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    items = []
    for key in TEST_BATCH_KEYS:
        _item = initial_item.copy()
        _item.update(key)
        items.append(dict_to_ddb(_item))

    client = boto3.client('dynamodb', region_name='us-west-2')
    e_client = EncryptedClient(
        client=client,
        materials_provider=materials_provider,
        attribute_actions=initial_actions
    )

    _put_result = e_client.batch_write_item(
        RequestItems={
            TEST_TABLE_NAME: [
                {'PutRequest': {'Item': _item}}
                for _item in items
            ]
        }
    )

    ddb_keys = [dict_to_ddb(key) for key in TEST_BATCH_KEYS]
    encrypted_result = client.batch_get_item(
        RequestItems={
            TEST_TABLE_NAME: {
                'Keys': ddb_keys
            }
        }
    )
    _check_encrypted_items(encrypted_result['Responses'][TEST_TABLE_NAME], items, check_attribute_actions)

    decrypted_result = e_client.batch_get_item(
        RequestItems={
            TEST_TABLE_NAME: {
                'Keys': ddb_keys
            }
        }
    )
    _assert_equal_lists_of_items(decrypted_result['Responses'][TEST_TABLE_NAME], items)

    _delete_result = e_client.batch_write_item(
        RequestItems={
            TEST_TABLE_NAME: [
                {'DeleteRequest': {'Key': _key}}
                for _key in ddb_keys
            ]
        }
    )
    raw_scan_result = client.scan(TableName=TEST_TABLE_NAME)
    e_scan_result = e_client.scan(TableName=TEST_TABLE_NAME)
    assert not raw_scan_result['Items']
    assert not e_scan_result['Items']

    del check_attribute_actions
    del items


def test_ephemeral_item_cycle(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _client_cycle_single_item_check(some_cmps, parametrized_actions, parametrized_item)


def test_ephemeral_batch_item_cycle(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _client_cycle_batch_items_check(some_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
def test_ephemeral_item_cycle_slow(example_table, all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    _client_cycle_single_item_check(all_the_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_slow(example_table, some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against a large number of items."""
    _client_cycle_single_item_check(some_cmps, parametrized_actions, item)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_veryslow(example_table, some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against ALL THE ITEMS."""
    _client_cycle_single_item_check(some_cmps, parametrized_actions, item)


@pytest.mark.nope
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_nope(example_table, all_the_cmps, parametrized_actions, item):
    """Test ALL THE CMPs against ALL THE ITEMS."""
    _client_cycle_single_item_check(all_the_cmps, parametrized_actions, item)
