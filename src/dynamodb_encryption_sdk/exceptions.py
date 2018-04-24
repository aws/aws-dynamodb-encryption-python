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
"""Exception classed for use in the DynamoDB Encryption Client."""


class DynamodbEncryptionSdkError(Exception):
    """Base class for all custom exceptions."""


class InvalidArgumentError(DynamodbEncryptionSdkError):
    """Raised when a general invalid argument is provided."""


class SerializationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered while serializing data."""


class DeserializationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered while deserializing data."""


class InvalidMaterialDescriptionError(DeserializationError):
    """Raised when errors are encountered processing a material description."""


class InvalidMaterialDescriptionVersionError(DeserializationError):
    """Raised when a material description is encountered with an invalid version."""


class InvalidAlgorithmError(InvalidArgumentError):
    """Raised when an invalid algorithm identifier is encountered."""


class JceTransformationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered when attempting to read a JCE transformation."""


class DelegatedKeyError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered by a DelegatedKey."""


class DelegatedKeyEncryptionError(DelegatedKeyError):
    """Raised when a DelegatedKey encounters an error during encryption."""


class DelegatedKeyDecryptionError(DelegatedKeyError):
    """Raised when a DelegatedKey encounters an error during decryption."""


class AwsKmsMaterialsProviderError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated errors encountered by the AwsKmsCryptographicMaterialsProvider."""


class UnknownRegionError(AwsKmsMaterialsProviderError):
    """Raised when the AwsKmsCryptographicMaterialsProvider is asked for an unknown region."""


class DecryptionError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while decrypting data."""


class UnwrappingError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while unwrapping a key."""


class EncryptionError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while encrypting data."""


class WrappingError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while wrapping a key."""


class SigningError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while signing data."""


class SignatureVerificationError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered while verifying a signature."""


class ProviderStoreError(DynamodbEncryptionSdkError):
    """Otherwise undifferentiated error encountered by a provider store."""


class NoKnownVersionError(ProviderStoreError):
    """Raised if a provider store cannot locate any version of the requested material."""


class InvalidVersionError(ProviderStoreError):
    """Raised if an invalid version of a material is requested."""


class VersionAlreadyExistsError(ProviderStoreError):
    """Raised if a version that is being added to a provider store already exists."""
