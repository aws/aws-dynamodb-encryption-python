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
"""Test ``wrapped_*_encrypted_*`` examples."""
import pytest
from dynamodb_encryption_sdk_examples import wrapped_rsa_encrypted_table, wrapped_symmetric_encrypted_table

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey

from .examples_test_utils import ddb_table_name  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.examples]


def test_wrapped_rsa_encrypted_table(ddb_table_name):
    wrapping_key_bytes = JceNameLocalDelegatedKey.generate("RSA", 4096).key
    signing_key_bytes = JceNameLocalDelegatedKey.generate("SHA512withRSA", 4096).key
    wrapped_rsa_encrypted_table.encrypt_item(ddb_table_name, wrapping_key_bytes, signing_key_bytes)


def test_wrapped_symmetric_encrypted_table(ddb_table_name):
    wrapping_key_bytes = JceNameLocalDelegatedKey.generate("AES", 256).key
    signing_key_bytes = JceNameLocalDelegatedKey.generate("HmacSHA512", 256).key
    wrapped_symmetric_encrypted_table.encrypt_item(ddb_table_name, wrapping_key_bytes, signing_key_bytes)
