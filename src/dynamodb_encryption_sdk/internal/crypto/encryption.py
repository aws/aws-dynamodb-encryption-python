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
"""Functions to handle encrypting and decrypting DynamoDB attributes.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Text  # noqa pylint: disable=unused-import
    from dynamodb_encryption_sdk.internal import dynamodb_types  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.internal.formatting.deserialize.attribute import deserialize_attribute
from dynamodb_encryption_sdk.internal.formatting.serialize.attribute import serialize_attribute
from dynamodb_encryption_sdk.internal.identifiers import Tag

__all__ = ('encrypt_attribute', 'decrypt_attribute')


def encrypt_attribute(attribute_name, attribute, encryption_key, algorithm):
    # type: (Text, dynamodb_types.RAW_ATTRIBUTE, DelegatedKey, Text) -> dynamodb_types.BINARY_ATTRIBUTE
    """Encrypt a single DynamoDB attribute.

    :param str attribute_name: DynamoDB attribute name
    :param dict attribute: Plaintext DynamoDB attribute
    :param DelegatedKey encryption_key: DelegatedKey to use to encrypt the attribute
    :param str algorithm: Encryption algorithm descriptor (passed to encryption_key as algorithm)
    :returns: Encrypted DynamoDB binary attribute
    :rtype: dict
    """
    serialized_attribute = serialize_attribute(attribute)
    encrypted_attribute = encryption_key.encrypt(
        algorithm=algorithm,
        name=attribute_name,
        plaintext=serialized_attribute
    )
    return {Tag.BINARY.dynamodb_tag: encrypted_attribute}


def decrypt_attribute(attribute_name, attribute, decryption_key, algorithm):
    # type: (Text, dynamodb_types.RAW_ATTRIBUTE, DelegatedKey, Text) -> dynamodb_types.RAW_ATTRIBUTE
    """Decrypt a single DynamoDB attribute.

    :param str attribute_name: DynamoDB attribute name
    :param dict attribute: Encrypted DynamoDB attribute
    :param DelegatedKey encryption_key: DelegatedKey to use to encrypt the attribute
    :param str algorithm: Decryption algorithm descriptor (passed to encryption_key as algorithm)
    :returns: Plaintext DynamoDB attribute
    :rtype: dict
    """
    encrypted_attribute = attribute[Tag.BINARY.dynamodb_tag]
    decrypted_attribute = decryption_key.decrypt(
        algorithm=algorithm,
        name=attribute_name,
        ciphertext=encrypted_attribute
    )
    return deserialize_attribute(decrypted_attribute)
