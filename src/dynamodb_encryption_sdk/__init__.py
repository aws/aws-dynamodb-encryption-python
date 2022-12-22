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
"""DynamoDB Encryption Client."""
import warnings

from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk.encrypted.item import (
    decrypt_dynamodb_item,
    decrypt_python_item,
    encrypt_dynamodb_item,
    encrypt_python_item,
)
from dynamodb_encryption_sdk.encrypted.resource import EncryptedResource
from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk.identifiers import __version__

__all__ = (
    "decrypt_dynamodb_item",
    "decrypt_python_item",
    "encrypt_dynamodb_item",
    "encrypt_python_item",
    "EncryptedClient",
    "EncryptedResource",
    "EncryptedTable",
    "__version__",
)

warnings.warn(
    "This major version (1.x) of the AWS DynamoDB Encryption Client for Python has reached End-of-Support.\n"
    + "It will no longer receive security updates or bug fixes.\n"
    + "Consider updating to the latest version of the AWS DynamoDB Encryption Client.",
    DeprecationWarning,
)
