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
"""Unique identifiers used by the DynamoDB Encryption Client."""
from enum import Enum

__all__ = ('LOGGER_NAME', 'CryptoAction', 'EncryptionKeyType', 'KeyEncodingType')
__version__ = '1.0.4'

LOGGER_NAME = 'dynamodb_encryption_sdk'
USER_AGENT_SUFFIX = 'DynamodbEncryptionSdkPython/{}'.format(__version__)


class CryptoAction(Enum):
    """Possible actions to take on an item attribute."""

    DO_NOTHING = 0
    SIGN_ONLY = 1
    ENCRYPT_AND_SIGN = 2

    def __gt__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return not self.__lt__(other) and not self.__eq__(other)

    def __lt__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return self.value < other.value

    def __eq__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return self.value == other.value


class EncryptionKeyType(Enum):
    """Supported types of encryption keys."""

    SYMMETRIC = 0
    PRIVATE = 1
    PUBLIC = 2


class KeyEncodingType(Enum):
    """Supported key encoding schemes."""

    RAW = 0
    DER = 1
    PEM = 2
