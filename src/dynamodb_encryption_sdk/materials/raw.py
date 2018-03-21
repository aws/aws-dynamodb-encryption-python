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
"""
Cryptographic materials classes for use directly with delegated keys.

.. warning::

    Using raw cryptographic materials can be very dangerous because you are likely to be
    encrypting many items using the same encryption key material. This can have some unexpected
    and difficult to detect side effects that weaken the security of your encrypted data.

    Unless you have specific reasons for using raw cryptographic materials, we highly recommend
    that you use wrapped cryptographic materials instead.
"""
import copy

import attr
import six

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey
from dynamodb_encryption_sdk.internal.validators import dictionary_validator
from dynamodb_encryption_sdk.materials import DecryptionMaterials, EncryptionMaterials

__all__ = ('RawEncryptionMaterials', 'RawDecryptionMaterials')


@attr.s(hash=False)
class RawEncryptionMaterials(EncryptionMaterials):
    """Encryption materials for use directly with delegated keys.

    .. note::

        Not all delegated keys allow use with raw cryptographic materials.

    :param signing_key: Delegated key used as signing key
    :type signing_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param encryption_key: Delegated key used as encryption key
    :type encryption_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param dict material_description: Material description to use with these cryptographic materials
    """
    _signing_key = attr.ib(validator=attr.validators.instance_of(DelegatedKey))
    _encryption_key = attr.ib(validator=attr.validators.instance_of(DelegatedKey))
    _material_description = attr.ib(
        validator=dictionary_validator(six.string_types, six.string_types),
        converter=copy.deepcopy,
        default=attr.Factory(dict)
    )

    def __attrs_post_init__(self):
        """Verify that the encryption key is allowed be used for raw materials."""
        if not self._encryption_key.allowed_for_raw_materials:
            raise ValueError('Encryption key type "{}" does not allow use with RawEncryptionMaterials'.format(
                type(self._encryption_key)
            ))

    @property
    def material_description(self):
        # type: () -> Dict[Text, Text]
        """Material description to use with these cryptographic materials.

        :returns: Material description
        :rtype: dict
        """
        return self._material_description

    @property
    def signing_key(self):
        # type: () -> Dict[Text, Text]
        """Delegated key used for calculating digital signatures.

        :returns: Signing key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        return self._signing_key

    @property
    def encryption_key(self):
        # type: () -> Dict[Text, Text]
        """Delegated key used for encrypting attributes.

        :returns: Encryption key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        return self._encryption_key


@attr.s(hash=False)
class RawDecryptionMaterials(DecryptionMaterials):
    """Encryption materials for use directly with delegated keys.

    .. note::

        Not all delegated keys allow use with raw cryptographic materials.

    :param verification_key: Delegated key used as verification key
    :type verification_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param decryption_key: Delegated key used as decryption key
    :type decryption_key: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
    :param dict material_description: Material description to use with these cryptographic materials
    """
    _verification_key = attr.ib(validator=attr.validators.instance_of(DelegatedKey))
    _decryption_key = attr.ib(validator=attr.validators.instance_of(DelegatedKey))
    _material_description = attr.ib(
        validator=dictionary_validator(six.string_types, six.string_types),
        converter=copy.deepcopy,
        default=attr.Factory(dict)
    )

    def __attrs_post_init__(self):
        """Verify that the encryption key is allowed be used for raw materials."""
        if not self._decryption_key.allowed_for_raw_materials:
            raise ValueError('Decryption key type "{}" does not allow use with RawDecryptionMaterials'.format(
                type(self._decryption_key)
            ))

    @property
    def material_description(self):
        # type: () -> Dict[Text, Text]
        """Material description to use with these cryptographic materials.

        :returns: Material description
        :rtype: dict
        """
        return self._material_description

    @property
    def verification_key(self):
        # type: () -> Dict[Text, Text]
        """Delegated key used for verifying digital signatures.

        :returns: Verification key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        return self._verification_key

    @property
    def decryption_key(self):
        # type: () -> Dict[Text, Text]
        """Delegated key used for decrypting attributes.

        :returns: Decryption key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        return self._decryption_key
