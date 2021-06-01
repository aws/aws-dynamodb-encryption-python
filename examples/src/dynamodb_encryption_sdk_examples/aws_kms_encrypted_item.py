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
"""Example showing use of AWS KMS CMP with item encryption functions directly."""
import boto3
from boto3.dynamodb.types import Binary

from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext, TableInfo
from dynamodb_encryption_sdk.transform import dict_to_ddb


def encrypt_item(table_name, aws_cmk_id):
    """Demonstrate use of EncryptedTable to transparently encrypt an item."""
    index_key = {"partition_attribute": "is this", "sort_attribute": 55}
    plaintext_item = {
        "example": "data",
        "some numbers": 99,
        "and some binary": Binary(b"\x00\x01\x02"),
        "leave me": "alone",  # We want to ignore this attribute
    }
    # Collect all of the attributes that will be encrypted (used later).
    encrypted_attributes = set(plaintext_item.keys())
    encrypted_attributes.remove("leave me")
    # Collect all of the attributes that will not be encrypted (used later).
    unencrypted_attributes = set(index_key.keys())
    unencrypted_attributes.add("leave me")
    # Add the index pairs to the item.
    plaintext_item.update(index_key)

    # Create a normal table resource.
    table = boto3.resource("dynamodb").Table(table_name)  # generated code confuse pylint: disable=no-member

    # Use the TableInfo helper to collect information about the indexes.
    table_info = TableInfo(name=table_name)
    table_info.refresh_indexed_attributes(table.meta.client)

    # Create a crypto materials provider using the specified AWS KMS key.
    aws_kms_cmp = AwsKmsCryptographicMaterialsProvider(key_id=aws_cmk_id)

    encryption_context = EncryptionContext(
        table_name=table_name,
        partition_key_name=table_info.primary_index.partition,
        sort_key_name=table_info.primary_index.sort,
        # The only attributes that are used by the AWS KMS cryptographic materials providers
        # are the primary index attributes.
        # These attributes need to be in the form of a DynamoDB JSON structure, so first
        # convert the standard dictionary.
        attributes=dict_to_ddb(index_key),
    )

    # Create attribute actions that tells the encrypted table to encrypt all attributes,
    # only sign the primary index attributes, and ignore the one identified attribute to
    # ignore.
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN, attribute_actions={"leave me": CryptoAction.DO_NOTHING}
    )
    actions.set_index_keys(*table_info.protected_index_keys())

    # Build the crypto config to use for this item.
    # When using the higher-level helpers, this is handled for you.
    crypto_config = CryptoConfig(
        materials_provider=aws_kms_cmp, encryption_context=encryption_context, attribute_actions=actions
    )

    # Encrypt the plaintext item directly
    encrypted_item = encrypt_python_item(plaintext_item, crypto_config)

    # You could now put the encrypted item to DynamoDB just as you would any other item.
    # table.put_item(Item=encrypted_item)
    # We will skip this for the purposes of this example.

    # Decrypt the encrypted item directly
    decrypted_item = decrypt_python_item(encrypted_item, crypto_config)

    # Verify that all of the attributes are different in the encrypted item
    for name in encrypted_attributes:
        assert encrypted_item[name] != plaintext_item[name]
        assert decrypted_item[name] == plaintext_item[name]

    # Verify that all of the attributes that should not be encrypted were not.
    for name in unencrypted_attributes:
        assert decrypted_item[name] == encrypted_item[name] == plaintext_item[name]
