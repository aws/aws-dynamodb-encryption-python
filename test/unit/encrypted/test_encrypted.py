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
"""Unit tests for ``dynamodb_encryption_sdk.encrypted``."""
import pytest

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from ..unit_test_utils import wrapped_cmp  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_with_item(wrapped_cmp):
    config = CryptoConfig(
        materials_provider=wrapped_cmp,
        encryption_context=EncryptionContext(attributes={}),
        attribute_actions=AttributeActions()
    )
    item = {
        'test': 'item',
        'with': 'some data'
    }
    new_config = config.with_item(item)

    assert config.encryption_context.attributes == {}
    assert new_config.encryption_context.attributes == item
