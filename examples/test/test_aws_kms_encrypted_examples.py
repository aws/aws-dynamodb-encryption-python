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
"""Test ``aws_kms_encrypted_*`` examples."""
import pytest

from ..src import aws_kms_encrypted_client, aws_kms_encrypted_item, aws_kms_encrypted_resource, aws_kms_encrypted_table
from .examples_test_utils import cmk_arn, ddb_table_name  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.examples]


def test_aws_kms_encrypted_table(ddb_table_name, cmk_arn):
    aws_kms_encrypted_table.encrypt_item(ddb_table_name, cmk_arn)


def test_aws_kms_encrypted_client_item(ddb_table_name, cmk_arn):
    aws_kms_encrypted_client.encrypt_item(ddb_table_name, cmk_arn)


def test_aws_kms_encrypted_client_batch_items(ddb_table_name, cmk_arn):
    aws_kms_encrypted_client.encrypt_batch_items(ddb_table_name, cmk_arn)


def test_aws_kms_encrypted_item(ddb_table_name, cmk_arn):
    aws_kms_encrypted_item.encrypt_item(ddb_table_name, cmk_arn)


def test_aws_kms_encrypted_resource(ddb_table_name, cmk_arn):
    aws_kms_encrypted_resource.encrypt_batch_items(ddb_table_name, cmk_arn)
