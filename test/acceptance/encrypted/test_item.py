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
"""Acceptance tests for ``dynamodb_encryption_sdk.encrypted.item``."""
import pytest

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.encrypted.item import decrypt_dynamodb_item
from dynamodb_encryption_sdk.structures import EncryptionContext
from ..acceptance_test_utils import load_scenarios

pytestmark = [pytest.mark.accept, pytest.mark.integ]


@pytest.mark.parametrize(
    'materials_provider, table_name, table_index, ciphertext_item, plaintext_item, attribute_actions',
    load_scenarios()
)
def test_item_encryptor(
        materials_provider,
        table_name,
        table_index,
        ciphertext_item,
        plaintext_item,
        attribute_actions
):
    encryption_context = EncryptionContext(
        table_name=table_name,
        partition_key_name=table_index['partition'],
        sort_key_name=table_index.get('sort', None),
        attributes=ciphertext_item
    )
    crypto_config = CryptoConfig(
        materials_provider=materials_provider,
        encryption_context=encryption_context,
        attribute_actions=attribute_actions
    )
    decrypted_item = decrypt_dynamodb_item(ciphertext_item.copy(), crypto_config)
    assert set(decrypted_item.keys()) == set(plaintext_item.keys())
    for key in decrypted_item:
        if key == 'version':
            continue
        assert decrypted_item[key] == plaintext_item[key]
