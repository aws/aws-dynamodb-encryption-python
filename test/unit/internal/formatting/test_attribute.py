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
"""Unit tests for ``dynamodb_encryption_sdk.internal.formatting.serialize.attribute``
and ``dynamodb_encryption_sdk.internal.formatting.deserialize.attribute``."""
import pytest

from dynamodb_encryption_sdk.internal.formatting.serialize.attribute import _sorted_key_map
from dynamodb_encryption_sdk.internal.str_ops import to_bytes

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize('initial, expected, transform', (
    (
        {
            'test': 'value',
            'zzz': 'another',
            'aaa': 'qqq',
            '?>?>?': 5,
            b'\x00\x00': None
        },
        [
            (b'\x00\x00', None, b'\x00\x00'),
            (b'?>?>?', 5, '?>?>?'),
            (b'aaa', 'qqq', 'aaa'),
            (b'test', 'value', 'test'),
            (b'zzz', 'another', 'zzz')
        ],
        to_bytes
    ),
))
def test_sorted_key_map(initial, expected, transform):
    actual = _sorted_key_map(initial, transform)

    assert actual == expected
