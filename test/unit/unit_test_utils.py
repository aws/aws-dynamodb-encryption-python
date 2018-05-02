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
"""Helper utilities for unit tests."""
import pytest

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider


@pytest.fixture
def wrapped_cmp():
    wrapping_key = JceNameLocalDelegatedKey.generate('AES', 256)
    signing_key = JceNameLocalDelegatedKey.generate('HmacSHA512', 256)
    cmp = WrappedCryptographicMaterialsProvider(
        signing_key=signing_key,
        wrapping_key=wrapping_key,
        unwrapping_key=wrapping_key
    )
    return cmp
