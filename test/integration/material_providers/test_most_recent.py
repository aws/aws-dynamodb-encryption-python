# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Load testing using MostRecentProvider and MetaStore."""
import boto3
import pytest

from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk.material_providers.most_recent import MostRecentProvider

from ..integration_test_utils import (  # pylint: disable=unused-import
    ddb_table_name,
    functional_test_utils,
    temp_metastore,
)

pytestmark = [pytest.mark.integ, pytest.mark.ddb_integ]


def count_entries(records, *messages):
    count = 0

    for record in records:
        if all((message in record.getMessage() for message in messages)):
            count += 1

    return count


def count_puts(records, table_name):
    return count_entries(records, '"TableName": "{}"'.format(table_name), "OperationModel(name=PutItem)")


def count_gets(records, table_name):
    return count_entries(records, '"TableName": "{}"'.format(table_name), "OperationModel(name=GetItem)")


def test_cache_use_encrypt(temp_metastore, ddb_table_name, caplog):
    table = boto3.resource("dynamodb").Table(ddb_table_name)

    e_table = EncryptedTable(
        table=table,
        materials_provider=MostRecentProvider(provider_store=temp_metastore, material_name="test", version_ttl=600.0),
    )

    item = functional_test_utils.diverse_item()
    item.update(functional_test_utils.TEST_KEY)
    e_table.put_item(Item=item)
    e_table.put_item(Item=item)
    e_table.put_item(Item=item)
    e_table.put_item(Item=item)

    e_table.delete_item(Key=functional_test_utils.TEST_KEY)

    primary_puts = count_puts(caplog.records, ddb_table_name)
    metastore_puts = count_puts(caplog.records, temp_metastore._table.name)

    assert primary_puts == 4
    assert metastore_puts == 1
