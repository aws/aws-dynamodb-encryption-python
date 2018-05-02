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
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Optional, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey
from dynamodb_encryption_sdk.exceptions import UnwrappingError, WrappingError
from dynamodb_encryption_sdk.internal.validators import dictionary_validator
from dynamodb_encryption_sdk.materials.wrapped import WrappedCryptographicMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext  # noqa pylint: disable=unused-import
from . import CryptographicMaterialsProvider

__all__ = ('WrappedCryptographicMaterialsProvider',)


@attr.s(init=False)
class WrappedCryptographicMaterialsProvider(CryptographicMaterialsProvider):
    """Cryptographic materials provider to use ephemeral content encryption keys wrapped by delegated keys.

    :param DelegatedKey signing_key: Delegated key used as signing and verification key
    :param DelegatedKey wrapping_key: Delegated key used to wrap content key

    .. note::

        ``wrapping_key`` must be provided if providing encryption materials

    :param DelegatedKey unwrapping_key: Delegated key used to unwrap content key

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
    _material_description = attr.ib(
        validator=attr.validators.optional(dictionary_validator(six.string_types, six.string_types)),
        default=attr.Factory(dict)
    )

    def __init__(
            self,
            signing_key,  # type: DelegatedKey
            wrapping_key=None,  # type: Optional[DelegatedKey]
            unwrapping_key=None,  # type: Optional[DelegatedKey]
            material_description=None  # type: Optional[Dict[Text, Text]]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        if material_description is None:
            material_description = {}

        self._signing_key = signing_key
        self._wrapping_key = wrapping_key
        self._unwrapping_key = unwrapping_key
        self._material_description = material_description
        attr.validate(self)

    def _build_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Construct

        :param EncryptionContext encryption_context: Encryption context for request
        :returns: Wrapped cryptographic materials
        :rtype: WrappedCryptographicMaterials
        """
        material_description = self._material_description.copy()
        material_description.update(encryption_context.material_description)
        return WrappedCryptographicMaterials(
            wrapping_key=self._wrapping_key,
            unwrapping_key=self._unwrapping_key,
            signing_key=self._signing_key,
            material_description=material_description
        )

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Provide encryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :returns: Encryption materials
        :rtype: WrappedCryptographicMaterials
        :raises WrappingError: if no wrapping key is available
        """
        if self._wrapping_key is None:
            raise WrappingError('Encryption materials cannot be provided: no wrapping key')

        return self._build_materials(encryption_context)

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> WrappedCryptographicMaterials
        """Provide decryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :returns: Decryption materials
        :rtype: WrappedCryptographicMaterials
        :raises UnwrappingError: if no unwrapping key is available
        """
        if self._unwrapping_key is None:
            raise UnwrappingError('Decryption materials cannot be provided: no unwrapping key')

        return self._build_materials(encryption_context)
