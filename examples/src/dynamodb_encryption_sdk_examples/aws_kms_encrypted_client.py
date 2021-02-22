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
"""Example showing use of AWS KMS CMP with EncryptedClient."""
import boto3

from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions


def encrypt_item(table_name, aws_cmk_id):
    """Demonstrate use of EncryptedClient to transparently encrypt an item."""
    index_key = {"partition_attribute": {"S": "is this"}, "sort_attribute": {"N": "55"}}
    plaintext_item = {
        "example": {"S": "data"},
        "some numbers": {"N": "99"},
        "and some binary": {"B": b"\x00\x01\x02"},
        "leave me": {"S": "alone"},  # We want to ignore this attribute
    }
    # Collect all of the attributes that will be encrypted (used later).
    encrypted_attributes = set(plaintext_item.keys())
    encrypted_attributes.remove("leave me")
    # Collect all of the attributes that will not be encrypted (used later).
    unencrypted_attributes = set(index_key.keys())
    unencrypted_attributes.add("leave me")
    # Add the index pairs to the item.
    plaintext_item.update(index_key)

    # Create a normal client.
    client = boto3.client("dynamodb")
    # Create a crypto materials provider using the specified AWS KMS key.
    aws_kms_cmp = AwsKmsCryptographicMaterialsProvider(key_id=aws_cmk_id)
    # Create attribute actions that tells the encrypted client to encrypt all attributes except one.
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN, attribute_actions={"leave me": CryptoAction.DO_NOTHING}
    )
    # Use these objects to create an encrypted client.
    encrypted_client = EncryptedClient(client=client, materials_provider=aws_kms_cmp, attribute_actions=actions)

    # Put the item to the table, using the encrypted client to transparently encrypt it.
    encrypted_client.put_item(TableName=table_name, Item=plaintext_item)

    # Get the encrypted item using the standard client.
    encrypted_item = client.get_item(TableName=table_name, Key=index_key)["Item"]

    # Get the item using the encrypted client, transparently decrypting it.
    decrypted_item = encrypted_client.get_item(TableName=table_name, Key=index_key)["Item"]

    # Verify that all of the attributes are different in the encrypted item
    for name in encrypted_attributes:
        assert encrypted_item[name] != plaintext_item[name]
        assert decrypted_item[name] == plaintext_item[name]

    # Verify that all of the attributes that should not be encrypted were not.
    for name in unencrypted_attributes:
        assert decrypted_item[name] == encrypted_item[name] == plaintext_item[name]

    # Clean up the item
    encrypted_client.delete_item(TableName=table_name, Key=index_key)


def encrypt_batch_items(table_name, aws_cmk_id):
    """Demonstrate use of EncryptedClient to transparently encrypt multiple items in a batch request."""
    index_keys = [
        {"partition_attribute": {"S": "is this"}, "sort_attribute": {"N": "55"}},
        {"partition_attribute": {"S": "is this"}, "sort_attribute": {"N": "56"}},
        {"partition_attribute": {"S": "is this"}, "sort_attribute": {"N": "57"}},
        {"partition_attribute": {"S": "another"}, "sort_attribute": {"N": "55"}},
    ]
    plaintext_additional_attributes = {
        "example": {"S": "data"},
        "some numbers": {"N": "99"},
        "and some binary": {"B": b"\x00\x01\x02"},
        "leave me": {"S": "alone"},  # We want to ignore this attribute
    }
    plaintext_items = []
    for key in index_keys:
        _attributes = key.copy()
        _attributes.update(plaintext_additional_attributes)
        plaintext_items.append(_attributes)

    # Collect all of the attributes that will be encrypted (used later).
    encrypted_attributes = set(plaintext_additional_attributes.keys())
    encrypted_attributes.remove("leave me")
    # Collect all of the attributes that will not be encrypted (used later).
    unencrypted_attributes = set(index_keys[0].keys())
    unencrypted_attributes.add("leave me")

    # Create a normal client.
    client = boto3.client("dynamodb")
    # Create a crypto materials provider using the specified AWS KMS key.
    aws_kms_cmp = AwsKmsCryptographicMaterialsProvider(key_id=aws_cmk_id)
    # Create attribute actions that tells the encrypted client to encrypt all attributes except one.
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN, attribute_actions={"leave me": CryptoAction.DO_NOTHING}
    )
    # Use these objects to create an encrypted client.
    encrypted_client = EncryptedClient(client=client, materials_provider=aws_kms_cmp, attribute_actions=actions)

    # Put the items to the table, using the encrypted client to transparently encrypt them.
    encrypted_client.batch_write_item(
        RequestItems={table_name: [{"PutRequest": {"Item": item}} for item in plaintext_items]}
    )

    # Get the encrypted item using the standard client.
    encrypted_items = client.batch_get_item(RequestItems={table_name: {"Keys": index_keys}})["Responses"][table_name]

    # Get the item using the encrypted client, transparently decyrpting it.
    decrypted_items = encrypted_client.batch_get_item(RequestItems={table_name: {"Keys": index_keys}})["Responses"][
        table_name
    ]

    def _select_index_from_item(item):
        """Find the index keys that match this item."""
        for index in index_keys:
            if all(item[key] == value for key, value in index.items()):
                return index

        raise Exception("Index key not found in item.")

    def _select_item_from_index(index, all_items):
        """Find the item that matches these index keys."""
        for item in all_items:
            if all(item[key] == value for key, value in index.items()):
                return item

        raise Exception("Index key not found in item.")

    for encrypted_item in encrypted_items:
        key = _select_index_from_item(encrypted_item)
        plaintext_item = _select_item_from_index(key, plaintext_items)
        decrypted_item = _select_item_from_index(key, decrypted_items)

        # Verify that all of the attributes are different in the encrypted item
        for name in encrypted_attributes:
            assert encrypted_item[name] != plaintext_item[name]
            assert decrypted_item[name] == plaintext_item[name]

        # Verify that all of the attributes that should not be encrypted were not.
        for name in unencrypted_attributes:
            assert decrypted_item[name] == encrypted_item[name] == plaintext_item[name]

    # Clean up the item
    encrypted_client.batch_write_item(
        RequestItems={table_name: [{"DeleteRequest": {"Key": key}} for key in index_keys]}
    )
