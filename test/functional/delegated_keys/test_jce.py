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
from __future__ import division

import logging

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.internal.crypto.jce_bridge.authentication import JAVA_AUTHENTICATOR
from dynamodb_encryption_sdk.internal.identifiers import MinimumKeySizes

pytestmark = [pytest.mark.functional, pytest.mark.local]


def _find_aes_key_length(key):
    return len(key) * 8


def _find_rsa_key_length(key):
    loaded_key = serialization.load_der_private_key(data=key, password=None, backend=default_backend())
    return loaded_key.key_size


@pytest.mark.parametrize(
    "algorithm, requested_bits, expected_bits, length_finder",
    (
        ("AES", 256, 256, _find_aes_key_length),
        ("AESWrap", 256, 256, _find_aes_key_length),
        ("RSA", 4096, 4096, _find_rsa_key_length),
        ("HmacSHA512", 256, 256, _find_aes_key_length),
        ("HmacSHA256", 256, 256, _find_aes_key_length),
        ("HmacSHA384", 256, 256, _find_aes_key_length),
        ("HmacSHA224", 256, 256, _find_aes_key_length),
        ("SHA512withRSA", 4096, 4096, _find_rsa_key_length),
        ("SHA256withRSA", 4096, 4096, _find_rsa_key_length),
        ("SHA384withRSA", 4096, 4096, _find_rsa_key_length),
        ("SHA224withRSA", 4096, 4096, _find_rsa_key_length),
    ),
)
def test_generate_correct_key_length(algorithm, requested_bits, expected_bits, length_finder):
    test = JceNameLocalDelegatedKey.generate(algorithm, requested_bits)

    assert length_finder(test.key) == expected_bits


def build_short_key_cases():
    for algorithm in JAVA_AUTHENTICATOR:
        if algorithm.upper().startswith("HMAC"):
            message = "HMAC keys smaller than {} bits are unsafe".format(MinimumKeySizes.HMAC.value)
            yield (algorithm, MinimumKeySizes.HMAC.value, False, message)
            yield (algorithm, MinimumKeySizes.HMAC.value - 1, True, message)

        elif algorithm.upper().endswith("RSA"):
            message = "RSA keys smaller than {} bits are unsafe".format(MinimumKeySizes.RSA.value)
            yield (algorithm, MinimumKeySizes.RSA.value, False, message)
            yield (algorithm, MinimumKeySizes.RSA.value // 2, True, message)

    message = "RSA keys smaller than {} bits are unsafe".format(MinimumKeySizes.RSA.value)
    yield ("RSA", MinimumKeySizes.RSA.value, False, message)
    yield ("RSA", MinimumKeySizes.RSA.value // 2, True, message)


@pytest.mark.travis_isolation
@pytest.mark.parametrize("algorithm, key_bits, too_short, error_message", build_short_key_cases())
def test_warn_on_short_keys(caplog, algorithm, key_bits, too_short, error_message):
    with caplog.at_level(logging.DEBUG):
        _test = JceNameLocalDelegatedKey.generate(algorithm, key_bits)  # noqa=F401

    logging_results = caplog.text
    assert (too_short and error_message in logging_results) or (not too_short and error_message not in logging_results)
