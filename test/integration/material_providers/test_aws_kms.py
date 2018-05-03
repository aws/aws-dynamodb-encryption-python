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
"""Integration tests for ``dynamodb_encryption_sdk.material_providers.aws_kms``."""
import logging
import itertools

from boto3.dynamodb.types import Binary
import hypothesis
import pytest

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.identifiers import CryptoAction, USER_AGENT_SUFFIX
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from dynamodb_encryption_sdk.transform import dict_to_ddb
from ..integration_test_utils import aws_kms_cmp  # noqa pylint: disable=unused-import
from ..integration_test_utils import functional_test_utils, hypothesis_strategies

pytestmark = pytest.mark.integ

_primary_key_names = ('partition_key', 'sort_key')


def pytest_generate_tests(metafunc):
    functional_test_utils.set_parametrized_actions(metafunc)
    functional_test_utils.set_parametrized_item(metafunc)


def test_verify_user_agent(aws_kms_cmp, caplog):
    caplog.set_level(level=logging.DEBUG)

    aws_kms_cmp.encryption_materials(EncryptionContext())

    assert USER_AGENT_SUFFIX in caplog.text


def _many_items():
    values = ('a string', 1234, Binary(b'binary \x00\x88 value'))
    partition_keys = (('partition_key', value) for value in values)
    sort_keys = (('sort_key', value) for value in values)
    for pairs in itertools.product(partition_keys, sort_keys):
        item = dict(pairs)
        yield pytest.param(item, id=str(item))


@pytest.mark.parametrize('item', _many_items())
def test_aws_kms_diverse_indexes(aws_kms_cmp, item):
    """Verify that AWS KMS cycle works for items with all possible combinations for primary index attribute types."""
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(
            partition_key_name='partition_key',
            sort_key_name='sort_key',
            attributes=dict_to_ddb(item)
        ),
        attribute_actions=AttributeActions(
            attribute_actions={
                key: CryptoAction.SIGN_ONLY
                for key in _primary_key_names
            }
        )
    )
    functional_test_utils.cycle_item_check(item, crypto_config)


def test_aws_kms_item_cycle(aws_kms_cmp, parametrized_actions, parametrized_item):
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    functional_test_utils.cycle_item_check(parametrized_item, crypto_config)


@pytest.mark.slow
@hypothesis_strategies.SLOW_SETTINGS
@hypothesis.given(item=hypothesis_strategies.ddb_items)
def test_aws_kms_item_cycle_hypothesis_slow(aws_kms_cmp, hypothesis_actions, item):
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(),
        attribute_actions=hypothesis_actions
    )
    functional_test_utils.cycle_item_check(item, crypto_config)


@pytest.mark.veryslow
@hypothesis_strategies.VERY_SLOW_SETTINGS
@hypothesis.given(item=hypothesis_strategies.ddb_items)
def test_aws_kms_item_cycle_hypothesis_veryslow(aws_kms_cmp, hypothesis_actions, item):
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(),
        attribute_actions=hypothesis_actions
    )
    functional_test_utils.cycle_item_check(item, crypto_config)
