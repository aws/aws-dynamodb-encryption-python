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
"""Functional tests for ``dynamodb_encryption_sdk.encrypted.table``."""
import hypothesis
import pytest

from ..functional_test_utils import (
    set_parametrized_actions, set_parametrized_cmp, set_parametrized_item,
    table_cycle_batch_writer_check, table_cycle_check, TEST_TABLE_NAME
)
from ..functional_test_utils import example_table  # noqa pylint: disable=unused-import
from ..hypothesis_strategies import ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS

pytestmark = [pytest.mark.functional, pytest.mark.local]


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


def _table_cycle_check(materials_provider, initial_actions, initial_item):
    return table_cycle_check(materials_provider, initial_actions, initial_item, TEST_TABLE_NAME, 'us-west-2')


def test_ephemeral_item_cycle(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _table_cycle_check(some_cmps, parametrized_actions, parametrized_item)


def test_ephemeral_item_cycle_batch_writer(example_table, some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    table_cycle_batch_writer_check(some_cmps, parametrized_actions, parametrized_item, TEST_TABLE_NAME, 'us-west-2')


@pytest.mark.slow
def test_ephemeral_item_cycle_slow(example_table, all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    _table_cycle_check(all_the_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
def test_ephemeral_item_cycle_batch_writer_slow(example_table, all_the_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    table_cycle_batch_writer_check(all_the_cmps, parametrized_actions, parametrized_item, TEST_TABLE_NAME, 'us-west-2')


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_slow(example_table, some_cmps, hypothesis_actions, item):
    """Test a small number of curated CMPs against a large number of items."""
    _table_cycle_check(some_cmps, hypothesis_actions, item)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_veryslow(example_table, some_cmps, hypothesis_actions, item):
    """Test a small number of curated CMPs against ALL THE ITEMS."""
    _table_cycle_check(some_cmps, hypothesis_actions, item)


@pytest.mark.nope
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_nope(example_table, all_the_cmps, hypothesis_actions, item):
    """Test ALL THE CMPs against ALL THE ITEMS."""
    _table_cycle_check(all_the_cmps, hypothesis_actions, item)
