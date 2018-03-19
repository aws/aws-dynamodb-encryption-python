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

from ..integration_test_utils import aws_kms_cmp, functional_test_utils, hypothesis_strategies
from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.structures import EncryptionContext

pytestmark = pytest.mark.integ


def pytest_generate_tests(metafunc):
    functional_test_utils.set_parametrized_actions(metafunc)
    functional_test_utils.set_parametrized_item(metafunc)


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
def test_aws_kms_item_cycle_hypothesis_slow(aws_kms_cmp, parametrized_actions, item):
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    functional_test_utils.cycle_item_check(item, crypto_config)


@pytest.mark.veryslow
@hypothesis_strategies.VERY_SLOW_SETTINGS
@hypothesis.given(item=hypothesis_strategies.ddb_items)
def test_aws_kms_item_cycle_hypothesis_veryslow(aws_kms_cmp, parametrized_actions, item):
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp,
        encryption_context=EncryptionContext(),
        attribute_actions=parametrized_actions
    )
    functional_test_utils.cycle_item_check(item, crypto_config)
