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
import operator

import pytest

from dynamodb_encryption_sdk.identifiers import ItemAction

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('left, right, expected', (
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.SIGN_ONLY, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.DO_NOTHING, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.SIGN_ONLY, ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY),
    (ItemAction.SIGN_ONLY, ItemAction.DO_NOTHING, ItemAction.SIGN_ONLY),
    (ItemAction.DO_NOTHING, ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.DO_NOTHING, ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY),
    (ItemAction.DO_NOTHING, ItemAction.DO_NOTHING, ItemAction.DO_NOTHING),
))
def test_item_action_max(left, right, expected):
    assert max(left, right) == expected


@pytest.mark.parametrize('left, right, expected', (
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.DO_NOTHING, ItemAction.DO_NOTHING),
    (ItemAction.SIGN_ONLY, ItemAction.ENCRYPT_AND_SIGN, ItemAction.SIGN_ONLY),
    (ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY),
    (ItemAction.SIGN_ONLY, ItemAction.DO_NOTHING, ItemAction.DO_NOTHING),
    (ItemAction.DO_NOTHING, ItemAction.ENCRYPT_AND_SIGN, ItemAction.DO_NOTHING),
    (ItemAction.DO_NOTHING, ItemAction.SIGN_ONLY, ItemAction.DO_NOTHING),
    (ItemAction.DO_NOTHING, ItemAction.DO_NOTHING, ItemAction.DO_NOTHING),
))
def test_item_action_min(left, right, expected):
    assert min(left, right) == expected


@pytest.mark.parametrize('left, right, expected_comparison', (
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.ENCRYPT_AND_SIGN, operator.eq),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.SIGN_ONLY, operator.ne),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.SIGN_ONLY, operator.gt),
    (ItemAction.ENCRYPT_AND_SIGN, ItemAction.DO_NOTHING, operator.gt),
    (ItemAction.SIGN_ONLY, ItemAction.ENCRYPT_AND_SIGN, operator.lt),
    (ItemAction.SIGN_ONLY, ItemAction.SIGN_ONLY, operator.eq),
    (ItemAction.SIGN_ONLY, ItemAction.DO_NOTHING, operator.ne),
    (ItemAction.SIGN_ONLY, ItemAction.DO_NOTHING, operator.gt),
    (ItemAction.DO_NOTHING, ItemAction.ENCRYPT_AND_SIGN, operator.lt),
    (ItemAction.DO_NOTHING, ItemAction.SIGN_ONLY, operator.lt),
    (ItemAction.DO_NOTHING, ItemAction.DO_NOTHING, operator.eq),
    (ItemAction.DO_NOTHING, ItemAction.ENCRYPT_AND_SIGN, operator.ne)
))
def test_item_action_comp(left, right, expected_comparison):
    assert expected_comparison(left, right)
