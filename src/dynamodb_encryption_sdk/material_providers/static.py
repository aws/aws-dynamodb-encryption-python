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

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.materials import CryptographicMaterials  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.materials import DecryptionMaterials, EncryptionMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext  # noqa pylint: disable=unused-import
from . import CryptographicMaterialsProvider

__all__ = ('StaticCryptographicMaterialsProvider',)


@attr.s(init=False)
class StaticCryptographicMaterialsProvider(CryptographicMaterialsProvider):
    """Manually combine encryption and decryption materials for use as a cryptographic materials provider.

    :param DecryptionMaterials decryption_materials: Decryption materials to provide (optional)
    :param EncryptionMaterials encryption_materials: Encryption materials to provide (optional)
    """

    _decryption_materials = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(DecryptionMaterials)),
        default=None
    )
    _encryption_materials = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(EncryptionMaterials)),
        default=None
    )

    def __init__(
            self,
            decryption_materials=None,  # type: Optional[DecryptionMaterials]
            encryption_materials=None  # type: Optional[EncryptionMaterials]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._decryption_materials = decryption_materials
        self._encryption_materials = encryption_materials
        attr.validate(self)

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return the static decryption materials.

        :param EncryptionContext encryption_context: Encryption context for request (not
            used by :class:`StaticCryptographicMaterialsProvider`)
        :raises AttributeError: if no decryption materials are available
        """
        if self._decryption_materials is None:
            return super(StaticCryptographicMaterialsProvider, self).decryption_materials(encryption_context)

        return self._decryption_materials

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return the static encryption materials.

        :param EncryptionContext encryption_context: Encryption context for request (not
            used by :class:`StaticCryptographicMaterialsProvider`)
        :raises AttributeError: if no encryption materials are available
        """
        if self._encryption_materials is None:
            return super(StaticCryptographicMaterialsProvider, self).encryption_materials(encryption_context)

        return self._encryption_materials
