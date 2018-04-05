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
"""Functional test suite for ``dynamodb_encryption_sdk.delegated_keys.jce``."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pytest

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey

pytestmark = [pytest.mark.functional, pytest.mark.local]


def _find_aes_key_length(key):
    return len(key) * 8


def _find_rsa_key_length(key):
    loaded_key = serialization.load_der_private_key(data=key, password=None, backend=default_backend())
    return loaded_key._key_size


@pytest.mark.parametrize('algorithm, requested_bits, expected_bits, length_finder', (
    ('AES', 256, 256, _find_aes_key_length),
    ('AESWrap', 256, 256, _find_aes_key_length),
    ('RSA', 4096, 4096, _find_rsa_key_length),
    ('HmacSHA512', 256, 256, _find_aes_key_length),
    ('HmacSHA256', 256, 256, _find_aes_key_length),
    ('HmacSHA384', 256, 256, _find_aes_key_length),
    ('HmacSHA224', 256, 256, _find_aes_key_length),
    ('SHA512withRSA', 4096, 4096, _find_rsa_key_length),
    ('SHA256withRSA', 4096, 4096, _find_rsa_key_length),
    ('SHA384withRSA', 4096, 4096, _find_rsa_key_length),
    ('SHA224withRSA', 4096, 4096, _find_rsa_key_length)
))
def test_generate_correct_key_length(algorithm, requested_bits, expected_bits, length_finder):
    test = JceNameLocalDelegatedKey.generate(algorithm, requested_bits)

    assert length_finder(test.key) == expected_bits
