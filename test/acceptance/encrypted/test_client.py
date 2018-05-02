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
"""Acceptance tests for ``dynamodb_encryption_sdk.encrypted.client``."""
import botocore
from mock import MagicMock
from moto import mock_dynamodb2
import pytest

from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk.structures import TableIndex, TableInfo
from dynamodb_encryption_sdk.transform import dict_to_ddb
from ..acceptance_test_utils import load_scenarios

pytestmark = [pytest.mark.accept]


def fake_client(table_name, item):
    client = MagicMock(__class__=botocore.client.BaseClient)
    client.get_item.return_value = {'Item': item.copy()}
    client.batch_get_item.return_value = {'Responses': {table_name: [item.copy()]}}
    return client


def _compare_item(plaintext_item, decrypted_item):
    assert set(decrypted_item.keys()) == set(plaintext_item.keys())
    for key in decrypted_item:
        if key == 'version':
            continue
        assert decrypted_item[key] == plaintext_item[key]


def _client_setup(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        attribute_actions,
        prep
):
    prep()  # Test scenario setup that needs to happen inside the test
    cmp = materials_provider()  # Some of the materials providers need to be constructed inside the test
    client = fake_client(table_name, ciphertext_item)
    table_info = TableInfo(
        name=table_name,
        primary_index=TableIndex(
            partition=table_index['partition'],
            sort=table_index.get('sort', None)
        )
    )
    item_key = {table_info.primary_index.partition: ciphertext_item[table_info.primary_index.partition]}
    if table_info.primary_index.sort is not None:
        item_key[table_info.primary_index.sort] = ciphertext_item[table_info.primary_index.sort]

    e_client = EncryptedClient(
        client=client,
        materials_provider=cmp,
        attribute_actions=attribute_actions,
        auto_refresh_table_indexes=False
    )
    e_client._table_info_cache._all_tables_info[table_name] = table_info
    return e_client, dict_to_ddb(item_key)


def _item_check(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
):
    e_client, item_key = _client_setup(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        attribute_actions,
        prep
    )
    decrypted_item = e_client.get_item(TableName=table_name, Key=item_key)['Item']
    _compare_item(plaintext_item, decrypted_item)


def _batch_items_check(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
):
    e_client, item_key = _client_setup(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        attribute_actions,
        prep
    )
    response = e_client.batch_get_item(RequestItems={table_name: {'Keys': [item_key]}})
    decrypted_item = response['Responses'][table_name][0]
    _compare_item(plaintext_item, decrypted_item)


def pytest_generate_tests(metafunc):
    if 'item_checker' in metafunc.fixturenames:
        metafunc.parametrize('item_checker', (
            pytest.param(_item_check, id='single-item'),
            pytest.param(_batch_items_check, id='batch-items')
        ))


@mock_dynamodb2
@pytest.mark.local
@pytest.mark.parametrize(
    'materials_provider, table_name, table_index, ciphertext_item, plaintext_item, attribute_actions, prep',
    load_scenarios(online=False)
)
def test_client_get_offline(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep,
        item_checker
):
    return item_checker(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
    )


@pytest.mark.integ
@pytest.mark.parametrize(
    'materials_provider, table_name, table_index, ciphertext_item, plaintext_item, attribute_actions, prep',
    load_scenarios(online=True)
)
def test_client_get_online(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep,
        item_checker
):
    return item_checker(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
    )
