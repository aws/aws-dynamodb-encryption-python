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
import hypothesis
import pytest

from .functional_test_utils import (
    build_static_jce_cmp, cycle_item_check, set_parametrized_actions, set_parametrized_cmp, set_parametrized_item
)
from .hypothesis_strategies import ddb_items, SLOW_SETTINGS, VERY_SLOW_SETTINGS
from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item
from dynamodb_encryption_sdk.exceptions import DecryptionError
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext

pytestmark = [pytest.mark.functional, pytest.mark.local]


def pytest_generate_tests(metafunc):
    set_parametrized_actions(metafunc)
    set_parametrized_cmp(metafunc)
    set_parametrized_item(metafunc)


def test_unsigned_item():
    crypto_config = CryptoConfig(
        materials_provider=build_static_jce_cmp('AES', 256, 'HmacSHA256', 256),
        encryption_context=EncryptionContext(),
        attribute_actions=AttributeActions()
    )
    item = {'test': 'no signature'}

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_python_item(item, crypto_config)

    exc_info.match(r'No signature attribute found in item')


def test_ephemeral_item_cycle(some_cmps, parametrized_actions, parametrized_item):
    """Test a small number of curated CMPs against a small number of curated items."""
    crypto_config = CryptoConfig(
        materials_provider=some_cmps,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    cycle_item_check(parametrized_item, crypto_config)


@pytest.mark.slow
def test_ephemeral_item_cycle_slow(all_the_cmps, parametrized_actions, parametrized_item):
    """Test ALL THE CMPS against a small number of curated items."""
    crypto_config = CryptoConfig(
        materials_provider=all_the_cmps,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    cycle_item_check(parametrized_item, crypto_config)


@pytest.mark.slow
@SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_slow(some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against a large number of items."""
    crypto_config = CryptoConfig(
        materials_provider=some_cmps,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    cycle_item_check(item, crypto_config)


@pytest.mark.veryslow
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_veryslow(some_cmps, parametrized_actions, item):
    """Test a small number of curated CMPs against ALL THE ITEMS."""
    crypto_config = CryptoConfig(
        materials_provider=some_cmps,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    cycle_item_check(item, crypto_config)


@pytest.mark.nope
@VERY_SLOW_SETTINGS
@hypothesis.given(item=ddb_items)
def test_ephemeral_item_cycle_hypothesis_nope(all_the_cmps, parametrized_actions, item):
    """Test ALL THE CMPs against ALL THE ITEMS."""
    crypto_config = CryptoConfig(
        materials_provider=all_the_cmps,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    cycle_item_check(item, crypto_config)
