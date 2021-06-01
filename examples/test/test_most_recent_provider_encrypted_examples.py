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
"""Test most recent provider examples."""
import uuid

import boto3
import pytest
from dynamodb_encryption_sdk_examples import most_recent_provider_encrypted_table

from dynamodb_encryption_sdk.material_providers.store.meta import MetaStore

from .examples_test_utils import cmk_arn, ddb_table_name  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.examples]


def test_most_recent_encrypted_table(ddb_table_name, cmk_arn):
    # define random new names for material and metastore table
    meta_table_name = "meta-table-{}".format(uuid.uuid4())
    material_name = "material-{}".format(uuid.uuid4())

    # create the metastore table
    client = boto3.client("dynamodb")
    MetaStore.create_table(client, meta_table_name, 10, 10)
    waiter = client.get_waiter("table_exists")
    waiter.wait(TableName=meta_table_name)

    # run the actual test
    most_recent_provider_encrypted_table.encrypt_item(ddb_table_name, cmk_arn, meta_table_name, material_name)

    # clean up the meta store table
    client.delete_table(TableName=meta_table_name)
    waiter = client.get_waiter("table_not_exists")
    waiter.wait(TableName=meta_table_name)
