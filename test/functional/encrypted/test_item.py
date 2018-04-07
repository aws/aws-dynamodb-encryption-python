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
"""Functional tests for ``dynamodb_encryption_sdk.encrypted.item``."""
import hypothesis
import pytest

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk.exceptions import DecryptionError, EncryptionError
from dynamodb_encryption_sdk.internal.identifiers import ReservedAttributes
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from ..functional_test_utils import (
    build_static_jce_cmp, cycle_item_check, set_parametrized_actions, set_parametrized_cmp, set_parametrized_item
)
from ..hypothesis_strategies import ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS

pytestmark = [pytest.mark.functional, pytest.mark.local]


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


@pytest.fixture
def static_cmp_crypto_config():
    return CryptoConfig(
        materials_provider=build_static_jce_cmp('AES', 256, 'HmacSHA256', 256),
        encryption_context=EncryptionContext(),
        attribute_actions=AttributeActions()
    )


def test_unsigned_item(static_cmp_crypto_config):
    item = {'test': 'no signature'}

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_python_item(item, static_cmp_crypto_config)

    exc_info.match(r'No signature attribute found in item')


@pytest.mark.parametrize('item', (
    {reserved.value: 'asdf'}
    for reserved in ReservedAttributes
))
def test_reserved_attributes_on_encrypt(static_cmp_crypto_config, item):
    with pytest.raises(EncryptionError) as exc_info:
        encrypt_python_item(item, static_cmp_crypto_config)

    exc_info.match(r'Reserved attribute name *')


def _item_cycle_check(materials_provider, attribute_actions, item):
    crypto_config = CryptoConfig(
        materials_provider=materials_provider,
        encryption_context=EncryptionContext(),
        attribute_actions=attribute_actions
    )
    cycle_item_check(item, crypto_config)


def test_ephemeral_item_cycle(some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    _item_cycle_check(some_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
def test_ephemeral_item_cycle_slow(all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    _item_cycle_check(all_the_cmps, parametrized_actions, parametrized_item)


@pytest.mark.slow
@pytest.mark.hypothesis
@SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_slow(some_cmps, hypothesis_actions, item):
    """Test a small number of curated CMPs against a large number of items."""
    _item_cycle_check(some_cmps, hypothesis_actions, item)


@pytest.mark.veryslow
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_veryslow(some_cmps, hypothesis_actions, item):
    """Test a small number of curated CMPs against ALL THE ITEMS."""
    _item_cycle_check(some_cmps, hypothesis_actions, item)


@pytest.mark.nope
@pytest.mark.hypothesis
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_nope(all_the_cmps, hypothesis_actions, item):
    """Test ALL THE CMPs against ALL THE ITEMS."""
    _item_cycle_check(all_the_cmps, hypothesis_actions, item)
