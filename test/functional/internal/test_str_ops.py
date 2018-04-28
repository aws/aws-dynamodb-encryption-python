# -*- coding: utf-8 -*-
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
"""Test suite for ``dynamodb_encryption_sdk.internal.str_ops``."""
import codecs

import pytest

from dynamodb_encryption_sdk.internal.str_ops import to_bytes, to_str

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('data, expected_output', (
    ('asdf', 'asdf'),
    (b'asdf', 'asdf'),
    (codecs.encode(u'Предисловие', 'utf-8'), u'Предисловие'),
    (u'Предисловие', u'Предисловие')
))
def test_to_str(data, expected_output):
    test = to_str(data)
    assert test == expected_output


@pytest.mark.parametrize('data, expected_output', (
    ('asdf', b'asdf'),
    (b'asdf', b'asdf'),
    (b'\x3a\x00\x99', b'\x3a\x00\x99'),
    (u'Предисловие', codecs.encode(u'Предисловие', 'utf-8')),
    (codecs.encode(u'Предисловие', 'utf-8'), codecs.encode(u'Предисловие', 'utf-8'))
))
def test_to_bytes(data, expected_output):
    test = to_bytes(data)
    assert test == expected_output
