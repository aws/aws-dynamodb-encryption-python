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
"""Functional test suite for ``dynamodb_encryption_sdk.materials.raw``."""
import pytest

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials

pytestmark = [pytest.mark.functional, pytest.mark.local]


def test_no_encryption_key():
    signing_key = JceNameLocalDelegatedKey.generate('HmacSHA512', 256)
    encryption_materials = RawEncryptionMaterials(signing_key=signing_key)

    with pytest.raises(AttributeError) as excinfo:
        encryption_materials.encryption_key

    excinfo.match('No encryption key available')


def test_no_decryption_key():
    verification_key = JceNameLocalDelegatedKey.generate('HmacSHA512', 256)
    decryption_materials = RawDecryptionMaterials(verification_key=verification_key)

    with pytest.raises(AttributeError) as excinfo:
        decryption_materials.decryption_key

    excinfo.match('No decryption key available')
