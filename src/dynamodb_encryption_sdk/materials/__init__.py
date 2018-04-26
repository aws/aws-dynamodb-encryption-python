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
"""Cryptographic materials are containers that provide delegated keys for cryptographic operations."""
import abc

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Text  # noqa pylint: disable=unused-import
    from mypy_extensions import NoReturn  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

import six

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey  # noqa pylint: disable=unused-import

__all__ = ('CryptographicMaterials', 'EncryptionMaterials', 'DecryptionMaterials')


@six.add_metaclass(abc.ABCMeta)
class CryptographicMaterials(object):
    """Base class for all cryptographic materials."""

    @abc.abstractproperty
    def material_description(self):
        # type: () -> Dict[Text, Text]
        """Material description to use with these cryptographic materials.

        :returns: Material description
        :rtype: dict
        """

    @abc.abstractproperty
    def encryption_key(self):
        # type: () -> DelegatedKey
        """Delegated key used for encrypting attributes.

        :returns: Encryption key
        :rtype: DelegatedKey
        """

    @abc.abstractproperty
    def decryption_key(self):
        # type: () -> DelegatedKey
        """Delegated key used for decrypting attributes.

        :returns: Decryption key
        :rtype: DelegatedKey
        """

    @abc.abstractproperty
    def signing_key(self):
        # type: () -> DelegatedKey
        """Delegated key used for calculating digital signatures.

        :returns: Signing key
        :rtype: DelegatedKey
        """

    @abc.abstractproperty
    def verification_key(self):
        # type: () -> DelegatedKey
        """Delegated key used for verifying digital signatures.

        :returns: Verification key
        :rtype: DelegatedKey
        """


class EncryptionMaterials(CryptographicMaterials):
    """Base class for all encryption materials."""

    @property
    def decryption_key(self):
        # type: () -> NoReturn
        """Encryption materials do not provide decryption keys.

        :raises NotImplementedError: because encryption materials do not contain decryption keys
        """
        raise NotImplementedError('Encryption materials do not provide decryption keys.')

    @property
    def verification_key(self):
        # type: () -> NoReturn
        """Encryption materials do not provide verification keys.

        :raises NotImplementedError: because encryption materials do not contain verification keys
        """
        raise NotImplementedError('Encryption materials do not provide verification keys.')


class DecryptionMaterials(CryptographicMaterials):
    """Base class for all decryption materials."""

    @property
    def encryption_key(self):
        # type: () -> NoReturn
        """Decryption materials do not provide encryption keys.

        :raises NotImplementedError: because decryption materials do not contain encryption keys
        """
        raise NotImplementedError('Decryption materials do not provide encryption keys.')

    @property
    def signing_key(self):
        # type: () -> NoReturn
        """Decryption materials do not provide signing keys.

        :raises NotImplementedError: because decryption materials do not contain signing keys
        """
        raise NotImplementedError('Decryption materials do not provide signing keys.')
