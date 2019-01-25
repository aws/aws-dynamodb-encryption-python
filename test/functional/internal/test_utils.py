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
from mock import Mock

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.internal.utils import encrypt_batch_write_item
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from dynamodb_encryption_sdk.transform import dict_to_ddb

from ..functional_test_utils import diverse_item


def get_test_item(standard_dict_format, partition_key, sort_key=None):
    attributes = diverse_item()

    attributes["partition-key"] = partition_key
    if sort_key is not None:
        attributes["sort-key"] = sort_key

    if not standard_dict_format:
        attributes = dict_to_ddb(attributes)
    return attributes


def get_test_items(standard_dict_format, table_name="table", with_sort_keys=False):

    if with_sort_keys:
        items = [
            get_test_item(standard_dict_format, partition_key="key-1", sort_key="sort-1"),
            get_test_item(standard_dict_format, partition_key="key-2", sort_key="sort-1"),
            get_test_item(standard_dict_format, partition_key="key-2", sort_key="sort-2"),
        ]
    else:
        items = [
            get_test_item(standard_dict_format, partition_key="key-1"),
            get_test_item(standard_dict_format, partition_key="key-2"),
        ]

    for pos, item in enumerate(items):
        item["encrypt-me"] = table_name + str(pos)

    return {table_name: [{"PutRequest": {"Item": item}} for item in items]}


def get_dummy_crypto_config(partition_key_name=None, sort_key_name=None, sign_keys=False):
    context = EncryptionContext(partition_key_name=partition_key_name, sort_key_name=sort_key_name)
    actions = AttributeActions(
        default_action=CryptoAction.DO_NOTHING, attribute_actions={"encrypt-me": CryptoAction.ENCRYPT_AND_SIGN}
    )
    if sign_keys:
        actions.attribute_actions["partition-key"] = CryptoAction.SIGN_ONLY
        actions.attribute_actions["sort-key"] = CryptoAction.SIGN_ONLY

    materials = Mock(spec=CryptographicMaterialsProvider)  # type: CryptographicMaterialsProvider
    return CryptoConfig(materials_provider=materials, encryption_context=context, attribute_actions=actions)


def check_encrypt_batch_write_item_call(request_items, crypto_config):
    def dummy_encrypt(item, **kwargs):
        result = item.copy()
        result["encrypt-me"] = "pretend Im encrypted"
        return result

    # execute a batch write, but make the write method return ALL the provided items as unprocessed
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
    "items", (get_test_items(standard_dict_format=True), get_test_items(standard_dict_format=False))
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_known_partition_key(items):
    crypto_config = get_dummy_crypto_config("partition-key")
    check_encrypt_batch_write_item_call(items, crypto_config)


@pytest.mark.parametrize(
    "items",
    (
        get_test_items(standard_dict_format=True, with_sort_keys=True),
        get_test_items(standard_dict_format=False, with_sort_keys=True),
    ),
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_known_partition_and_sort_keys(items):
    crypto_config = get_dummy_crypto_config("partition-key", "sort-key")
    check_encrypt_batch_write_item_call(items, crypto_config)


@pytest.mark.parametrize(
    "items",
    (
        get_test_items(standard_dict_format=True),
        get_test_items(standard_dict_format=False),
        get_test_items(standard_dict_format=True, with_sort_keys=True),
        get_test_items(standard_dict_format=False, with_sort_keys=True),
    ),
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_unknown_keys(items):
    crypto_config = get_dummy_crypto_config(None, None)

    check_encrypt_batch_write_item_call(items, crypto_config)


@pytest.mark.parametrize(
    "items",
    (
        get_test_items(standard_dict_format=True),
        get_test_items(standard_dict_format=False),
        get_test_items(standard_dict_format=True, with_sort_keys=True),
        get_test_items(standard_dict_format=False, with_sort_keys=True),
    ),
)
def test_encrypt_batch_write_returns_plaintext_unprocessed_items_with_unknown_signed_keys(items):
    crypto_config = get_dummy_crypto_config(None, None, sign_keys=True)

    check_encrypt_batch_write_item_call(items, crypto_config)


def test_encrypt_batch_write_returns_plaintext_unprocessed_items_over_multiple_tables():
    crypto_config = get_dummy_crypto_config("partition-key", "sort-key")

    items = get_test_items(standard_dict_format=True, table_name="table-one", with_sort_keys=True)
    more_items = get_test_items(standard_dict_format=False, table_name="table-two", with_sort_keys=True)
    items.update(more_items)

    check_encrypt_batch_write_item_call(items, crypto_config)
