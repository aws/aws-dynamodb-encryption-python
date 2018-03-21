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
"""Cryptographic materials provider for use with pre-configured encryption and decryption materials."""
import attr

from . import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials import DecryptionMaterials, EncryptionMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext

__all__ = ('StaticCryptographicMaterialsProvider',)


@attr.s
class StaticCryptographicMaterialsProvider(CryptographicMaterialsProvider):
    """Manually combine encryption and decryption materials for use as a cryptographic materials provider.

    :param decryption_materials: Decryption materials to provide (optional)
    :type decryption_materials: dynamodb_encryption_sdk.materials.DecryptionMaterials
    :param encryption_materials: Encryption materials to provide (optional)
    :type encryption_materials: dynamodb_encryption_sdk.materials.EncryptionMaterials
    """
    _decryption_materials = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(DecryptionMaterials)),
        default=None
    )
    _encryption_materials = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(EncryptionMaterials)),
        default=None
    )

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> DecryptionMaterials
        """Return the static decryption materials.

        :param encryption_context: Encryption context for request (not used by ``StaticCryptographicMaterialsProvider``)
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :raises AttributeError: if no decryption materials are available
        """
        if self._decryption_materials is None:
            super(StaticCryptographicMaterialsProvider, self).decryption_materials(encryption_context)

        return self._decryption_materials

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> EncryptionMaterials
        """Return the static encryption materials.

        :param encryption_context: Encryption context for request (not used by ``StaticCryptographicMaterialsProvider``)
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :raises AttributeError: if no encryption materials are available
        """
        if self._encryption_materials is None:
            super(StaticCryptographicMaterialsProvider, self).encryption_materials(encryption_context)

        return self._encryption_materials
