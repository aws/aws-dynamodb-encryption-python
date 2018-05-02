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
"""Acceptance tests for ``dynamodb_encryption_sdk.encrypted.table``."""
from boto3.resources.base import ServiceResource
from mock import MagicMock
from moto import mock_dynamodb2
import pytest

from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk.structures import TableIndex, TableInfo
from dynamodb_encryption_sdk.transform import ddb_to_dict
from ..acceptance_test_utils import load_scenarios

pytestmark = [pytest.mark.accept]


def fake_table(item):
    table = MagicMock(__class__=ServiceResource)
    table.get_item.return_value = {'Item': item}
    return table


def _item_check(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
):
    ciphertext_item = ddb_to_dict(ciphertext_item)
    plaintext_item = ddb_to_dict(plaintext_item)
    prep()  # Test scenario setup that needs to happen inside the test
    cmp = materials_provider()  # Some of the materials providers need to be constructed inside the test
    table = fake_table(ciphertext_item)
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

    e_table = EncryptedTable(
        table=table,
        materials_provider=cmp,
        table_info=table_info,
        attribute_actions=attribute_actions,
        auto_refresh_table_indexes=False
    )
    decrypted_item = e_table.get_item(Key=item_key)['Item']
    assert set(decrypted_item.keys()) == set(plaintext_item.keys())
    for key in decrypted_item:
        if key == 'version':
            continue
        assert decrypted_item[key] == plaintext_item[key]


@mock_dynamodb2
@pytest.mark.local
@pytest.mark.parametrize(
    'materials_provider, table_name, table_index, ciphertext_item, plaintext_item, attribute_actions, prep',
    load_scenarios(online=False)
)
def test_table_get_offline(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
):
    return _item_check(
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
def test_table_get_online(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
):
    return _item_check(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions,
        prep
    )
