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
"""Cryptographic materials provider to use ephemeral content encryption keys wrapped by delegated keys."""
import attr

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey
from dynamodb_encryption_sdk.exceptions import UnwrappingError, WrappingError
from dynamodb_encryption_sdk.materials.wrapped import WrappedCryptographicMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext  # noqa pylint: disable=unused-import
from . import CryptographicMaterialsProvider

__all__ = ('WrappedCryptographicMaterialsProvider',)


@attr.s(init=False)
class WrappedCryptographicMaterialsProvider(CryptographicMaterialsProvider):
    """Cryptographic materials provider to use ephemeral content encryption keys wrapped by delegated keys.

    :param signing_key: Delegated key used as signing and verification key
    :type signing_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param wrapping_key: Delegated key used to wrap content key
    :type wrapping_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey

    .. note::

        ``wrapping_key`` must be provided if providing encryption materials

    :param unwrapping_key: Delegated key used to unwrap content key
    :type unwrapping_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey

    .. note::

        ``unwrapping_key`` must be provided if providing decryption materials or loading
        materials from material description
    """

    _signing_key = attr.ib(validator=attr.validators.instance_of(DelegatedKey))
    _wrapping_key = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(DelegatedKey)),
        default=None
    )
    _unwrapping_key = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(DelegatedKey)),
        default=None
    )

    def __init__(
            self,
            signing_key,  # type: DelegatedKey
            wrapping_key=None,  # type: Optional[DelegatedKey]
            unwrapping_key=None  # type: Optional[DelegatedKey]
    ):
        # type: (...) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
        self._signing_key = signing_key
        self._wrapping_key = wrapping_key
        self._unwrapping_key = unwrapping_key
        attr.validate(self)

    def _build_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Construct

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Wrapped cryptographic materials
        :rtype: dynamodb_encryption_sdk.materials.wrapped.WrappedCryptographicMaterials
        """
        return WrappedCryptographicMaterials(
            wrapping_key=self._wrapping_key,
            unwrapping_key=self._unwrapping_key,
            signing_key=self._signing_key,
            material_description=encryption_context.material_description.copy()
        )

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Provide encryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Encryption materials
        :rtype: dynamodb_encryption_sdk.materials.wrapped.WrappedCryptographicMaterials
        :raises WrappingError: if no wrapping key is available
        """
        if self._wrapping_key is None:
            raise WrappingError('Encryption materials cannot be provided: no wrapping key')

        return self._build_materials(encryption_context)

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Provide decryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Decryption materials
        :rtype: dynamodb_encryption_sdk.materials.wrapped.WrappedCryptographicMaterials
        :raises UnwrappingError: if no unwrapping key is available
        """
        if self._unwrapping_key is None:
            raise UnwrappingError('Decryption materials cannot be provided: no unwrapping key')

        return self._build_materials(encryption_context)
