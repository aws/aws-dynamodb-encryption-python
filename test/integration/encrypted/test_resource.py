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
"""Integration tests for ``dynamodb_encryption_sdk.encrypted.resource``."""
import pytest

from ..integration_test_utils import aws_kms_cmp, ddb_table_name  # noqa pylint: disable=unused-import
from ..integration_test_utils import functional_test_utils

pytestmark = [pytest.mark.integ, pytest.mark.ddb_integ]


def pytest_generate_tests(metafunc):
    functional_test_utils.set_parametrized_actions(metafunc)
    functional_test_utils.set_parametrized_cmp(metafunc)
    functional_test_utils.set_parametrized_item(metafunc)


def test_ephemeral_batch_item_cycle(ddb_table_name, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    functional_test_utils.resource_cycle_batch_items_check(
        some_cmps,
        parametrized_actions,
        parametrized_item,
        ddb_table_name
    )


def test_ephemeral_batch_item_cycle_kms(ddb_table_name, aws_kms_cmp, parametrized_actions, parametrized_item):
    """Test the AWS KMS CMP against a small number of curated items."""
    functional_test_utils.resource_cycle_batch_items_check(
        aws_kms_cmp,
        parametrized_actions,
        parametrized_item,
        ddb_table_name
    )
