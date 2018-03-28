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
"""Functions to handle calculating and verifying signatures of encrypted items."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.encrypted import CryptoConfig  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.identifiers import ItemAction
from dynamodb_encryption_sdk.internal.formatting.serialize.attribute import serialize_attribute
from dynamodb_encryption_sdk.internal.identifiers import SignatureValues, Tag
from dynamodb_encryption_sdk.structures import AttributeActions  # noqa pylint: disable=unused-import

__all__ = ('sign_item', 'verify_item_signature')


def sign_item(encrypted_item, signing_key, crypto_config):
    # type: (dynamodb_types.ITEM, DelegatedKey, CryptoConfig) -> dynamodb_types.BINARY_ATTRIBUTE
    """Generate the signature DynamoDB atttribute.

    :param dict encrypted_item: Encrypted DynamoDB item
    :param signing_key: DelegatedKey to use to calculate the signature
    :type signing_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param crypto_config: Cryptographic configuration
    :type crypto_config: dynamodb_encryption_sdk.encrypted.CryptoConfig
    :returns: Item signature DynamoDB attribute value
    :rtype: dict
    """
    signature = signing_key.sign(
        algorithm=signing_key.algorithm,
        data=_string_to_sign(
            item=encrypted_item,
            table_name=crypto_config.encryption_context.table_name,
            attribute_actions=crypto_config.attribute_actions
        )
    )
    return {Tag.BINARY.dynamodb_tag: signature}


def verify_item_signature(signature_attribute, encrypted_item, verification_key, crypto_config):
    # type: (dynamodb_types.BINARY_ATTRIBUTE, dynamodb_types.ITEM, DelegatedKey, CryptoConfig) -> None
    """Verify the item signature.

    :param dict signature_attribute: Item signature DynamoDB attribute value
    :param dict encrypted_item: Encrypted DynamoDB item
    :param verification_key: DelegatedKey to use to calculate the signature
    :type verification_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param crypto_config: Cryptographic configuration
    :type crypto_config: dynamodb_encryption_sdk.encrypted.CryptoConfig
    """
    signature = signature_attribute[Tag.BINARY.dynamodb_tag]
    verification_key.verify(
        algorithm=verification_key.algorithm,
        signature=signature,
        data=_string_to_sign(
            item=encrypted_item,
            table_name=crypto_config.encryption_context.table_name,
            attribute_actions=crypto_config.attribute_actions
        )
    )


def _string_to_sign(item, table_name, attribute_actions):
    # type: (dynamodb_type.ITEM, Text, AttributeActions) -> bytes
    """Generate the string to sign from an encrypted item and configuration.

    :param dict item: Encrypted DynamoDB item
    :param str table_name: Table name to use when generating the string to sign
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    """
    hasher = hashes.Hash(
        hashes.SHA256(),
        backend=default_backend()
    )
    data_to_sign = bytearray()
    data_to_sign.extend(_hash_data(
        hasher=hasher,
        data='TABLE>{}<TABLE'.format(table_name).encode('utf-8')
    ))
    for key in sorted(item.keys()):
        action = attribute_actions.action(key)
        if action is ItemAction.DO_NOTHING:
            continue

        data_to_sign.extend(_hash_data(
            hasher=hasher,
            data=key.encode('utf-8')
        ))

        if action is ItemAction.SIGN_ONLY:
            data_to_sign.extend(SignatureValues.PLAINTEXT.sha256)
        else:
            data_to_sign.extend(SignatureValues.ENCRYPTED.sha256)

        data_to_sign.extend(_hash_data(
            hasher=hasher,
            data=serialize_attribute(item[key])
        ))
    return bytes(data_to_sign)


def _hash_data(hasher, data):
    """Generate hash of data using provided hash type.

    :param hasher: Hasher instance to use as a base for calculating hash
    :type hasher: cryptography.hazmat.primitives.hashes.Hash
    :param bytes data: Data to sign
    :returns: Hash of data
    :rtype: bytes
    """
    _hasher = hasher.copy()
    _hasher.update(data)
    return _hasher.finalize()
