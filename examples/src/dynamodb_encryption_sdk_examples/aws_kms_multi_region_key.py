# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example showing use of AWS KMS CMP with a DynamoDB Global table and an AWS Multi-Region Key."""

import time

import boto3

from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions

SECOND_REGION = "eu-west-1"


def encrypt_item(table_name, cmk_mrk_arn_first_region, cmk_mrk_arn_second_region):
    """Demonstrate use of Multi-Region Keys with DynamoDB Encryption Client.

    This example encrypts an item with a Multi-Region Key in one region and decrypts it in another region. It
    assumes that you have a Dynamo DB Global table in two regions, as well as a KMS
    Multi-Region Key replicated to these regions.
    """
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

    # Create attribute actions that tells the encrypted client to encrypt all attributes except one.
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN, attribute_actions={"leave me": CryptoAction.DO_NOTHING}
    )

    # Create a DDB client and KMS crypto materials provider in the first region using the specified AWS KMS key.
    split_arn = cmk_mrk_arn_first_region.split(":")
    encryption_region = split_arn[3]
    ddb_client = boto3.client("dynamodb", region_name=encryption_region)
    encryption_cmp = AwsKmsCryptographicMaterialsProvider(key_id=cmk_mrk_arn_first_region)
    # Use these objects to create an encrypted client.
    encryption_client = EncryptedClient(client=ddb_client, materials_provider=encryption_cmp, attribute_actions=actions)

    # Put the item to the table, using the encrypted client to transparently encrypt it.
    encryption_client.put_item(TableName=table_name, Item=plaintext_item)

    # Create a DDB client and KMS crypto materials provider in the second region
    split_arn = cmk_mrk_arn_second_region.split(":")
    decryption_region = split_arn[3]
    decryption_cmp = AwsKmsCryptographicMaterialsProvider(key_id=cmk_mrk_arn_second_region)
    ddb_client = boto3.client("dynamodb", region_name=decryption_region)
    # Use these objects to create an encrypted client.
    decryption_client = EncryptedClient(client=ddb_client, materials_provider=decryption_cmp, attribute_actions=actions)

    # DDB Global Table replication takes some time. Sleep for a moment to give the item a chance to replicate to the
    # second region
    time.sleep(1)

    # Get the item from the second region, transparently decrypting it. This allows you to avoid a cross-region KMS
    # call to the first region if your application is running in the second region
    decrypted_item = decryption_client.get_item(TableName=table_name, Key=index_key)["Item"]

    # Verify that the decryption successfully retrieved the original plaintext
    for name in encrypted_attributes:
        assert plaintext_item[name] == decrypted_item[name]

    # Clean up the item
    encryption_client.delete_item(TableName=table_name, Key=index_key)
