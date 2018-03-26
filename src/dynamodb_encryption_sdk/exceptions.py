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


class DynamodbEncryptionSdkError(Exception):
    """Base class for all custom exceptions."""


class InvalidArgumentError(DynamodbEncryptionSdkError):
    """"""


class SerializationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered while serializing data."""


class DeserializationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered while deserializing data."""


class InvalidMaterialDescriptionError(DeserializationError):
    """Raised when errors are encountered processing a material description."""


class InvalidMaterialDescriptionVersionError(DeserializationError):
    """Raised when a material description is encountered with an invalid version."""


class InvalidAlgorithmError(DynamodbEncryptionSdkError):
    """Raised when an invalid algorithm identifier is encountered."""


class JceTransformationError(DynamodbEncryptionSdkError):
    """"""


class DelegatedKeyError(DynamodbEncryptionSdkError):
    """"""


class DelegatedKeyEncryptionError(DelegatedKeyError):
    """"""


class DelegatedKeyDecryptionError(DelegatedKeyError):
    """"""


class AwsKmsMaterialsProviderError(DynamodbEncryptionSdkError):
    """"""


class UnknownRegionError(AwsKmsMaterialsProviderError):
    """"""


class DecryptionError(DynamodbEncryptionSdkError):
    """"""


class UnwrappingError(DynamodbEncryptionSdkError):
    """"""


class EncryptionError(DynamodbEncryptionSdkError):
    """"""


class WrappingError(DynamodbEncryptionSdkError):
    """"""


class SigningError(DynamodbEncryptionSdkError):
    """"""


class SignatureVerificationError(DynamodbEncryptionSdkError):
    """"""
