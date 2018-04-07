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
"""Functional tests for material description de/serialization."""
import pytest

from dynamodb_encryption_sdk.internal.crypto.authentication import _string_to_sign
from ...functional_test_vector_generators import string_to_sign_test_vectors

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('item, table_name, attribute_actions, expected_result', string_to_sign_test_vectors())
def test_string_to_sign(item, table_name, attribute_actions, expected_result):
    generated_string = _string_to_sign(item, table_name, attribute_actions)
    assert generated_string == expected_result
