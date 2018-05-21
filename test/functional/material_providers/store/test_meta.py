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
"""Functional tests for ``dynamodb_encryption_sdk.material_providers.store.meta``."""
import base64
import os

import boto3
from moto import mock_dynamodb2
import pytest

from dynamodb_encryption_sdk.material_providers.store.meta import MetaStore

pytestmark = [pytest.mark.functional, pytest.mark.local]


@mock_dynamodb2
def test_create_table():
    client = boto3.client('dynamodb', region_name='us-west-2')
    table_name = base64.b64encode(os.urandom(32)).decode('utf-8')

    MetaStore.create_table(client, table_name, 1, 1)
    waiter = client.get_waiter('table_exists')
    waiter.wait(TableName=table_name)

    client.delete_table(TableName=table_name)
    waiter = client.get_waiter('table_not_exists')
    waiter.wait(TableName=table_name)
