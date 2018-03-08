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
from decimal import Decimal

import boto3
import hypothesis
from moto import mock_dynamodb2
import pytest

from .functional_test_utils import (
    check_encrypted_item, set_parametrized_actions, set_parametrized_cmp, set_parametrized_item
)
from .hypothesis_strategies import ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS
from dynamodb_encryption_sdk.encrypted.table import EncryptedTable

pytestmark = [pytest.mark.functional, pytest.mark.local]
_TABLE_NAME = 'my_table'
_INDEX = {
    'partition_attribute': {
        'type': 'S',
        'value': 'test_value'
    },
    'sort_attribute': {
        'type': 'N',
        'value':  Decimal('99.233')
    }
}
_KEY = {name: value['value'] for name, value in _INDEX.items()}


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


@pytest.fixture(scope='module')
def example_table():
    mock_dynamodb2().start()
    ddb = boto3.resource('dynamodb', region_name='us-west-2')
    ddb.create_table(
        TableName=_TABLE_NAME,
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
            for name, value in _INDEX.items()
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 100,
            'WriteCapacityUnits': 100
        }
    )
    yield
    mock_dynamodb2().stop()


def _table_cycle_check(materials_manager, initial_actions, initial_item):
    attribute_actions = initial_actions.copy()
    item = initial_item.copy()
    item.update(_KEY)

    table = boto3.resource('dynamodb', region_name='us-west-2').Table(_TABLE_NAME)
    e_table = EncryptedTable(
        table=table,
        materials_provider=materials_manager,
        attribute_actions=attribute_actions,
    )

    _put_result = e_table.put_item(Item=item)

    encrypted_result = table.get_item(Key=_KEY)
    check_encrypted_item(item, encrypted_result['Item'], attribute_actions)

    decrypted_result = e_table.get_item(Key=_KEY)
    assert decrypted_result['Item'] == item

    e_table.delete_item(Key=_KEY)


def test_ephemeral_item_cycle(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _table_cycle_check(some_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
def test_ephemeral_item_cycle_slow(example_table, all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    _table_cycle_check(all_the_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_slow(example_table, some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against a large number of items."""
    _table_cycle_check(some_cmps, parametrized_actions, item)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_veryslow(example_table, some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against ALL THE ITEMS."""
    _table_cycle_check(some_cmps, parametrized_actions, item)


@pytest.mark.nope
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_nope(example_table, all_the_cmps, parametrized_actions, item):
    """Test ALL THE CMPs against ALL THE ITEMS."""
    _table_cycle_check(all_the_cmps, parametrized_actions, item)
