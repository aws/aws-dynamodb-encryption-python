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
"""Unique identifiers for internal use only.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
from enum import Enum

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Optional, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = (
    'ReservedAttributes', 'Tag', 'TagValues', 'TEXT_ENCODING',
    'SignatureValues', 'MaterialDescriptionKeys', 'MaterialDescriptionValues'
)

#: Encoding to use for all text values.
#: This is noted here for consistency but should not be changed.
TEXT_ENCODING = 'utf-8'


class ReservedAttributes(Enum):
    """Item attributes reserved for use by DynamoDBEncryptionClient"""

    MATERIAL_DESCRIPTION = '*amzn-ddb-map-desc*'
    SIGNATURE = '*amzn-ddb-map-sig*'


class Tag(Enum):
    """Attribute data type identifiers used for serialization and deserialization of attributes."""

    BINARY = (b'b', 'B')
    BINARY_SET = (b'B', 'BS', b'b')
    NUMBER = (b'n', 'N')
    NUMBER_SET = (b'N', 'NS', b'n')
    STRING = (b's', 'S')
    STRING_SET = (b'S', 'SS', b's')
    BOOLEAN = (b'?', 'BOOL')
    NULL = (b'\x00', 'NULL')
    LIST = (b'L', 'L')
    MAP = (b'M', 'M')

    def __init__(self, tag, dynamodb_tag, element_tag=None):
        # type: (bytes, Text, Optional[bytes]) -> None
        """Sets up new Tag object.

        :param bytes tag: DynamoDB Encryption SDK tag
        :param bytes dynamodb_tag: DynamoDB tag
        :param bytes element_tag: The type of tag contained within attributes of this type
        """
        self.tag = tag
        self.dynamodb_tag = dynamodb_tag
        self.element_tag = element_tag


class TagValues(Enum):
    """Static values to use when serializing attribute values."""

    FALSE = b'\x00'
    TRUE = b'\x01'


class SignatureValues(Enum):
    """Values used when building the string to sign.

    .. note::

        The only time we actually use these values, we use the SHA256 hash of the value, so
        we pre-compute these hashes here.
    """

    ENCRYPTED = (
        b'ENCRYPTED',
        b"9A\x15\xacN\xb0\x9a\xa4\x94)4\x88\x16\xb2\x03\x81'\xb0\xf9\xe3\xa5 7*\xe1\x00\xca\x19\xfb\x08\xfdP"
    )
    PLAINTEXT = (
        b'PLAINTEXT',
        b'\xcb@\xe7\xda\xdc\x86\x16\x1b\x97\x98\xdeHQ/3-!\xc1A\xfc\xc1\xe2\x8a\x08o\xdeJ3u\xaa\xb1\xb5'
    )

    def __init__(self, raw, sha256):
        # type: (bytes, bytes) -> None
        """Set up a new :class:`SignatureValues` object.

        :param bytes raw: Raw value
        :param bytes sha256: SHA256 hash of raw value
        """
        self.raw = raw
        self.sha256 = sha256


class MaterialDescriptionKeys(Enum):
    """Static keys for use when building and reading material descriptions."""

    ATTRIBUTE_ENCRYPTION_MODE = 'amzn-ddb-map-sym-mode'
    SIGNING_KEY_ALGORITHM = 'amzn-ddb-map-signingAlg'
    WRAPPED_DATA_KEY = 'amzn-ddb-env-key'
    CONTENT_ENCRYPTION_ALGORITHM = 'amzn-ddb-env-alg'
    CONTENT_KEY_WRAPPING_ALGORITHM = 'amzn-ddb-wrap-alg'
    ITEM_SIGNATURE_ALGORITHM = 'amzn-ddb-sig-alg'


class MaterialDescriptionValues(Enum):
    """Static default values for use when building material descriptions."""

    CBC_PKCS5_ATTRIBUTE_ENCRYPTION = '/CBC/PKCS5Padding'
