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
"""Top-level functions for encrypting and decrypting DynamoDB items."""
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from dynamodb_encryption_sdk.internal import dynamodb_types  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import DecryptionError, EncryptionError
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.internal.crypto.authentication import sign_item, verify_item_signature
from dynamodb_encryption_sdk.internal.crypto.encryption import decrypt_attribute, encrypt_attribute
from dynamodb_encryption_sdk.internal.formatting.material_description import (
    deserialize as deserialize_material_description, serialize as serialize_material_description
)
from dynamodb_encryption_sdk.internal.identifiers import (
    MaterialDescriptionKeys, MaterialDescriptionValues, ReservedAttributes
)
from dynamodb_encryption_sdk.transform import ddb_to_dict, dict_to_ddb
from . import CryptoConfig  # noqa pylint: disable=unused-import

__all__ = ('encrypt_dynamodb_item', 'encrypt_python_item', 'decrypt_dynamodb_item', 'decrypt_python_item')


def encrypt_dynamodb_item(item, crypto_config):
    # type: (dynamodb_types.ITEM, CryptoConfig) -> dynamodb_types.ITEM
    """Encrypt a DynamoDB item.

    >>> from dynamodb_encryption_sdk.encrypted.item import encrypt_dynamodb_item
    >>> plaintext_item = {
    ...     'some': {'S': 'data'},
    ...     'more': {'N': '5'}
    ... }
    >>> encrypted_item = encrypt_dynamodb_item(
    ...     item=plaintext_item,
    ...     crypto_config=my_crypto_config
    ... )

    .. note::

        This handles DynamoDB-formatted items and is for use with the boto3 DynamoDB client.

    :param dict item: Plaintext DynamoDB item
    :param CryptoConfig crypto_config: Cryptographic configuration
    :returns: Encrypted and signed DynamoDB item
    :rtype: dict
    """
    if crypto_config.attribute_actions.take_no_actions:
        # If we explicitly have been told not to do anything to this item, just copy it.
        return item.copy()

    for reserved_name in ReservedAttributes:
        if reserved_name.value in item:
            raise EncryptionError('Reserved attribute name "{}" is not allowed in plaintext item.'.format(
                reserved_name.value
            ))

    crypto_config.materials_provider.refresh()
    encryption_materials = crypto_config.encryption_materials()

    inner_material_description = encryption_materials.material_description.copy()
    try:
        encryption_materials.encryption_key
    except AttributeError:
        if crypto_config.attribute_actions.contains_action(CryptoAction.ENCRYPT_AND_SIGN):
            raise EncryptionError(
                'Attribute actions ask for some attributes to be encrypted but no encryption key is available'
            )

        encrypted_item = item.copy()
    else:
        # Add the attribute encryption mode to the inner material description
        encryption_mode = MaterialDescriptionValues.CBC_PKCS5_ATTRIBUTE_ENCRYPTION.value
        inner_material_description[
            MaterialDescriptionKeys.ATTRIBUTE_ENCRYPTION_MODE.value
        ] = encryption_mode

        algorithm_descriptor = encryption_materials.encryption_key.algorithm + encryption_mode

        encrypted_item = {}
        for name, attribute in item.items():
            if crypto_config.attribute_actions.action(name) is CryptoAction.ENCRYPT_AND_SIGN:
                encrypted_item[name] = encrypt_attribute(
                    attribute_name=name,
                    attribute=attribute,
                    encryption_key=encryption_materials.encryption_key,
                    algorithm=algorithm_descriptor
                )
            else:
                encrypted_item[name] = attribute.copy()

    signature_attribute = sign_item(encrypted_item, encryption_materials.signing_key, crypto_config)
    encrypted_item[ReservedAttributes.SIGNATURE.value] = signature_attribute

    try:
        # Add the signing key algorithm identifier to the inner material description if provided
        inner_material_description[
            MaterialDescriptionKeys.SIGNING_KEY_ALGORITHM.value
        ] = encryption_materials.signing_key.signing_algorithm()
    except NotImplementedError:
        # Not all signing keys will provide this value
        pass

    material_description_attribute = serialize_material_description(inner_material_description)
    encrypted_item[ReservedAttributes.MATERIAL_DESCRIPTION.value] = material_description_attribute

    return encrypted_item


def encrypt_python_item(item, crypto_config):
    # type: (dynamodb_types.ITEM, CryptoConfig) -> dynamodb_types.ITEM
    """Encrypt a dictionary for DynamoDB.

    >>> from dynamodb_encryption_sdk.encrypted.item import encrypt_python_item
    >>> plaintext_item = {
    ...     'some': 'data',
    ...     'more': 5
    ... }
    >>> encrypted_item = encrypt_python_item(
    ...     item=plaintext_item,
    ...     crypto_config=my_crypto_config
    ... )

    .. note::

        This handles human-friendly dictionaries and is for use with the boto3 DynamoDB service or table resource.

    :param dict item: Plaintext dictionary
    :param CryptoConfig crypto_config: Cryptographic configuration
    :returns: Encrypted and signed dictionary
    :rtype: dict
    """
    ddb_item = dict_to_ddb(item)
    encrypted_ddb_item = encrypt_dynamodb_item(ddb_item, crypto_config)
    return ddb_to_dict(encrypted_ddb_item)


def decrypt_dynamodb_item(item, crypto_config):
    # type: (dynamodb_types.ITEM, CryptoConfig) -> dynamodb_types.ITEM
    """Decrypt a DynamoDB item.

    >>> from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item
    >>> encrypted_item = {
    ...     'some': {'B': b'ENCRYPTED_DATA'},
    ...     'more': {'B': b'ENCRYPTED_DATA'}
    ... }
    >>> decrypted_item = decrypt_python_item(
    ...     item=encrypted_item,
    ...     crypto_config=my_crypto_config
    ... )

    .. note::

        This handles DynamoDB-formatted items and is for use with the boto3 DynamoDB client.

    :param dict item: Encrypted and signed DynamoDB item
    :param CryptoConfig crypto_config: Cryptographic configuration
    :returns: Plaintext DynamoDB item
    :rtype: dict
    """
    unique_actions = set([crypto_config.attribute_actions.default_action.name])
    unique_actions.update(set([action.name for action in crypto_config.attribute_actions.attribute_actions.values()]))

    if crypto_config.attribute_actions.take_no_actions:
        # If we explicitly have been told not to do anything to this item, just copy it.
        return item.copy()

    try:
        signature_attribute = item.pop(ReservedAttributes.SIGNATURE.value)
    except KeyError:
        # The signature is always written, so if no signature is found then the item was not
        # encrypted or signed.
        raise DecryptionError('No signature attribute found in item')

    inner_crypto_config = crypto_config.copy()
    # Retrieve the material description from the item if found.
    try:
        material_description_attribute = item.pop(ReservedAttributes.MATERIAL_DESCRIPTION.value)
    except KeyError:
        # If no material description is found, we use inner_crypto_config as-is.
        pass
    else:
        # If material description is found, override the material description in inner_crypto_config.
        material_description = deserialize_material_description(material_description_attribute)
        inner_crypto_config.encryption_context.material_description = material_description

    decryption_materials = inner_crypto_config.decryption_materials()

    verify_item_signature(signature_attribute, item, decryption_materials.verification_key, inner_crypto_config)

    try:
        decryption_key = decryption_materials.decryption_key
    except AttributeError:
        if inner_crypto_config.attribute_actions.contains_action(CryptoAction.ENCRYPT_AND_SIGN):
            raise DecryptionError(
                'Attribute actions ask for some attributes to be decrypted but no decryption key is available'
            )

        return item.copy()

    decryption_mode = inner_crypto_config.encryption_context.material_description.get(
        MaterialDescriptionKeys.ATTRIBUTE_ENCRYPTION_MODE.value
    )
    algorithm_descriptor = decryption_key.algorithm + decryption_mode

    # Once the signature has been verified, actually decrypt the item attributes.
    decrypted_item = {}
    for name, attribute in item.items():
        if inner_crypto_config.attribute_actions.action(name) is CryptoAction.ENCRYPT_AND_SIGN:
            decrypted_item[name] = decrypt_attribute(
                attribute_name=name,
                attribute=attribute,
                decryption_key=decryption_key,
                algorithm=algorithm_descriptor
            )
        else:
            decrypted_item[name] = attribute.copy()

    return decrypted_item


def decrypt_python_item(item, crypto_config):
    # type: (dynamodb_types.ITEM, CryptoConfig) -> dynamodb_types.ITEM
    """Decrypt a dictionary for DynamoDB.

    >>> from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item
    >>> encrypted_item = {
    ...     'some': Binary(b'ENCRYPTED_DATA'),
    ...     'more': Binary(b'ENCRYPTED_DATA')
    ... }
    >>> decrypted_item = decrypt_python_item(
    ...     item=encrypted_item,
    ...     crypto_config=my_crypto_config
    ... )

    .. note::

        This handles human-friendly dictionaries and is for use with the boto3 DynamoDB service or table resource.

    :param dict item: Encrypted and signed dictionary
    :param CryptoConfig crypto_config: Cryptographic configuration
    :returns: Plaintext dictionary
    :rtype: dict
    """
    ddb_item = dict_to_ddb(item)
    decrypted_ddb_item = decrypt_dynamodb_item(ddb_item, crypto_config)
    return ddb_to_dict(decrypted_ddb_item)
