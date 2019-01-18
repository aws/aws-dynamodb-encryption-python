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
"""Test suite for ``dynamodb_encryption_sdk.internal.utils``."""
import copy

import pytest

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.internal.utils import encrypt_batch_write_item
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from dynamodb_encryption_sdk.transform import ddb_to_dict

from ..functional_test_vector_generators import attribute_test_vectors


def get_test_item(standard_dict_format, partition_key, sort_key):
    attributes = attribute_test_vectors("serialize")

    attributes = {"attr_" + str(pos): attribute[0] for pos, attribute in enumerate(attributes)}
    attributes["partition-key"] = {"S": partition_key}
    if sort_key:
        attributes["sort-key"] = {"S": sort_key}

    if standard_dict_format:
        attributes = ddb_to_dict(attributes)
    return attributes


def get_test_items(standard_dict_format, table_name="table"):
    items = [
        get_test_item(standard_dict_format, partition_key="key-1", sort_key=None),
        get_test_item(standard_dict_format, partition_key="key-2", sort_key=None),
        get_test_item(standard_dict_format, partition_key="key-3", sort_key="sort-1"),
        get_test_item(standard_dict_format, partition_key="key-4", sort_key="sort-1"),
        get_test_item(standard_dict_format, partition_key="key-4", sort_key="sort-2"),
    ]

    for pos, item in enumerate(items):
        item["encrypt-me"] = table_name + str(pos)

    return {table_name: [{"PutRequest": {"Item": item}} for item in items]}


def get_dummy_crypto_config(partition_key_name, sort_key_name, encrypted_attribute_name):
    context = EncryptionContext(partition_key_name=partition_key_name, sort_key_name=sort_key_name)
    actions = AttributeActions(
        default_action=CryptoAction.DO_NOTHING,
        attribute_actions={encrypted_attribute_name: CryptoAction.ENCRYPT_AND_SIGN},
    )
    materials = CryptographicMaterialsProvider()
    return CryptoConfig(materials_provider=materials, encryption_context=context, attribute_actions=actions)


def check_encrypt_batch_write_item_call(request_items, crypto_config, encrypted_attribute_name):
    def dummy_encrypt(item, **kwargs):
        result = item.copy()
        result[encrypted_attribute_name] = "pretend Im encrypted"
        return result

    result = encrypt_batch_write_item(
        encrypt_method=dummy_encrypt,
        write_method=lambda **kwargs: {"UnprocessedItems": kwargs["RequestItems"]},
        crypto_config_method=lambda **kwargs: crypto_config,
        RequestItems=copy.deepcopy(request_items),
    )

    # assert the returned items equal the submitted items
    unprocessed = result["UnprocessedItems"]

    assert unprocessed == request_items


@pytest.mark.parametrize(
    "items",
    (
        (get_test_items(standard_dict_format=True)),
        (get_test_items(standard_dict_format=False))
    )
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_known_keys(items):
    crypto_config = get_dummy_crypto_config("partition-key", "sort-key", encrypted_attribute_name="encrypt-me")

    check_encrypt_batch_write_item_call(items, crypto_config, encrypted_attribute_name="encrypt-me")


@pytest.mark.parametrize(
    "items",
    (
        (get_test_items(standard_dict_format=True)),
        (get_test_items(standard_dict_format=False))
    )
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_unknown_keys(items):
    crypto_config = get_dummy_crypto_config(None, None, encrypted_attribute_name="encrypt-me")

    check_encrypt_batch_write_item_call(items, crypto_config, encrypted_attribute_name="encrypt-me")


def test_encrypt_batch_write_returns_plaintext_unprocessed_items_over_multiple_tables():
    crypto_config = get_dummy_crypto_config("partition-key", "sort-key", encrypted_attribute_name="encrypt-me")

    items = get_test_items(False, "table-one")
    more_items = get_test_items(False, "table-two")
    items.update(more_items)

    check_encrypt_batch_write_item_call(items, crypto_config, encrypted_attribute_name="encrypt-me")
