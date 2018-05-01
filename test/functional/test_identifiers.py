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
"""Functional tests for ``dynamodb_encryption_sdk.identifiers``."""
import operator

import pytest

from dynamodb_encryption_sdk.identifiers import CryptoAction

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('left, right, expected', (
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.DO_NOTHING, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.SIGN_ONLY, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY),
    (CryptoAction.SIGN_ONLY, CryptoAction.DO_NOTHING, CryptoAction.SIGN_ONLY),
    (CryptoAction.DO_NOTHING, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.DO_NOTHING, CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY),
    (CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING),
))
def test_item_action_max(left, right, expected):
    assert max(left, right) == expected


@pytest.mark.parametrize('left, right, expected', (
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING),
    (CryptoAction.SIGN_ONLY, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY),
    (CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY),
    (CryptoAction.SIGN_ONLY, CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING),
    (CryptoAction.DO_NOTHING, CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.DO_NOTHING),
    (CryptoAction.DO_NOTHING, CryptoAction.SIGN_ONLY, CryptoAction.DO_NOTHING),
    (CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING),
))
def test_item_action_min(left, right, expected):
    assert min(left, right) == expected


@pytest.mark.parametrize('left, right, expected_comparison', (
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.ENCRYPT_AND_SIGN, operator.eq),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY, operator.ne),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY, operator.gt),
    (CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.DO_NOTHING, operator.gt),
    (CryptoAction.SIGN_ONLY, CryptoAction.ENCRYPT_AND_SIGN, operator.lt),
    (CryptoAction.SIGN_ONLY, CryptoAction.SIGN_ONLY, operator.eq),
    (CryptoAction.SIGN_ONLY, CryptoAction.DO_NOTHING, operator.ne),
    (CryptoAction.SIGN_ONLY, CryptoAction.DO_NOTHING, operator.gt),
    (CryptoAction.DO_NOTHING, CryptoAction.ENCRYPT_AND_SIGN, operator.lt),
    (CryptoAction.DO_NOTHING, CryptoAction.SIGN_ONLY, operator.lt),
    (CryptoAction.DO_NOTHING, CryptoAction.DO_NOTHING, operator.eq),
    (CryptoAction.DO_NOTHING, CryptoAction.ENCRYPT_AND_SIGN, operator.ne)
))
def test_item_action_comp(left, right, expected_comparison):
    assert expected_comparison(left, right)
