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
"""Example showing use of a RSA wrapped CMP with EncryptedTable."""
import boto3
from boto3.dynamodb.types import Binary

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk.identifiers import CryptoAction, EncryptionKeyType, KeyEncodingType
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions


def encrypt_item(table_name, rsa_wrapping_private_key_bytes, rsa_signing_private_key_bytes):
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
    # Create a crypto materials provider using the provided wrapping and signing keys.
    # We show private keys used here, but public keys could be used as well, allowing
    # only wrapping or signature verification.
    wrapping_key = JceNameLocalDelegatedKey(
        key=rsa_wrapping_private_key_bytes,
        algorithm="RSA",
        key_type=EncryptionKeyType.PRIVATE,
        key_encoding=KeyEncodingType.DER,
    )
    signing_key = JceNameLocalDelegatedKey(
        key=rsa_signing_private_key_bytes,
        algorithm="SHA512withRSA",
        key_type=EncryptionKeyType.PRIVATE,
        key_encoding=KeyEncodingType.DER,
    )
    wrapped_cmp = WrappedCryptographicMaterialsProvider(
        wrapping_key=wrapping_key, unwrapping_key=wrapping_key, signing_key=signing_key
    )
    # Create attribute actions that tells the encrypted table to encrypt all attributes except one.
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN, attribute_actions={"leave me": CryptoAction.DO_NOTHING}
    )
    # Use these objects to create an encrypted table resource.
    encrypted_table = EncryptedTable(table=table, materials_provider=wrapped_cmp, attribute_actions=actions)

    # Put the item to the table, using the encrypted table resource to transparently encrypt it.
    encrypted_table.put_item(Item=plaintext_item)

    # Get the encrypted item using the standard table resource.
    encrypted_item = table.get_item(Key=index_key)["Item"]

    # Get the item using the encrypted table resource, transparently decyrpting it.
    decrypted_item = encrypted_table.get_item(Key=index_key)["Item"]

    # Verify that all of the attributes are different in the encrypted item
    for name in encrypted_attributes:
        assert encrypted_item[name] != plaintext_item[name]
        assert decrypted_item[name] == plaintext_item[name]

    # Verify that all of the attributes that should not be encrypted were not.
    for name in unencrypted_attributes:
        assert decrypted_item[name] == encrypted_item[name] == plaintext_item[name]

    # Clean up the item
    encrypted_table.delete_item(Key=index_key)
