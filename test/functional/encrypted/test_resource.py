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
"""Functional tests for ``dynamodb_encryption_sdk.encrypted.resource``."""
import boto3
import pytest

from dynamodb_encryption_sdk.encrypted.resource import EncryptedResource
from ..functional_test_utils import (
    cycle_batch_item_check, set_parametrized_actions, set_parametrized_cmp, set_parametrized_item, TEST_TABLE_NAME
)
from ..functional_test_utils import example_table  # noqa

pytestmark = [pytest.mark.functional, pytest.mark.local]


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


def _resource_cycle_batch_items_check(materials_provider, initial_actions, initial_item):
    resource = boto3.resource('dynamodb', region_name='us-west-2')
    e_resource = EncryptedResource(
        resource=resource,
        materials_provider=materials_provider,
        attribute_actions=initial_actions
    )

    cycle_batch_item_check(
        raw=resource,
        encrypted=e_resource,
        initial_actions=initial_actions,
        initial_item=initial_item
    )

    raw_scan_result = resource.Table(TEST_TABLE_NAME).scan()
    e_scan_result = e_resource.Table(TEST_TABLE_NAME).scan()
    assert not raw_scan_result['Items']
    assert not e_scan_result['Items']


def test_ephemeral_batch_item_cycle(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _resource_cycle_batch_items_check(some_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
def test_ephemeral_batch_item_cycle_slow(example_table, all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    _resource_cycle_batch_items_check(all_the_cmps, parametrized_actions, parametrized_item)
