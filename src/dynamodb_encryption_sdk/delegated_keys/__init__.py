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
"""Delegated keys."""
import abc
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Optional, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

import six

from dynamodb_encryption_sdk.identifiers import EncryptionKeyType  # noqa pylint: disable=unused-import

__all__ = ('DelegatedKey',)


def _raise_not_implemented(method_name):
    """Raises a standardized :class:`NotImplementedError` to report that the specified method
    is not supported.

    :raises NotImplementedError: when called
    """
    raise NotImplementedError('"{}" is not supported by this DelegatedKey'.format(method_name))


@six.add_metaclass(abc.ABCMeta)
class DelegatedKey(object):
    """Delegated keys are black boxes that encrypt, decrypt, sign, and verify data and wrap
    and unwrap keys. Not all delegated keys implement all methods.

    Unless overridden by a subclass, any method that a delegated key does not implement raises
    a :class:`NotImplementedError` detailing this.
    """

    @abc.abstractproperty
    def algorithm(self):
        # type: () -> Text
        """Text description of algorithm used by this delegated key."""

    @property
    def allowed_for_raw_materials(self):
        # type: () -> bool
        """Most delegated keys should not be used with :class:`RawDecryptionMaterials` or
        :class:`RawEncryptionMaterials`.

        :returns: False
        :rtype: bool
        """
        return False

    @classmethod
    def generate(cls, algorithm, key_length):  # type: ignore
        # type: (Text, int) -> DelegatedKey
        # pylint: disable=unused-argument,no-self-use
        """Generate an instance of this :class:`DelegatedKey` using the specified algorithm and key length.

        :param str algorithm: Text description of algorithm to be used
        :param int key_length: Size of key to generate
        :returns: Generated delegated key
        :rtype: DelegatedKey
        """
        _raise_not_implemented('generate')

    def encrypt(self, algorithm, name, plaintext, additional_associated_data=None):  # type: ignore
        # type: (Text, Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument,no-self-use
        """Encrypt data.

        :param str algorithm: Text description of algorithm to use to encrypt data
        :param str name: Name associated with plaintext data
        :param bytes plaintext: Plaintext data to encrypt
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on encrypt it must be required on decrypt.
        :returns: Encrypted ciphertext
        :rtype: bytes
        """
        _raise_not_implemented('encrypt')

    def decrypt(self, algorithm, name, ciphertext, additional_associated_data=None):  # type: ignore
        # type: (Text, Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument,no-self-use
        """Encrypt data.

        :param str algorithm: Text description of algorithm to use to decrypt data
        :param str name: Name associated with ciphertext data
        :param bytes ciphertext: Ciphertext data to decrypt
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on encrypt it must be required on decrypt.
        :returns: Decrypted plaintext
        :rtype: bytes
        """
        _raise_not_implemented('decrypt')

    def wrap(self, algorithm, content_key, additional_associated_data=None):  # type: ignore
        # type: (Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument,no-self-use
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to wrap key
        :param bytes content_key: Raw content key to wrap
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on wrap it must be required on unwrap.
        :returns: Wrapped key
        :rtype: bytes
        """
        _raise_not_implemented('wrap')

    def unwrap(  # type: ignore
            self,
            algorithm,
            wrapped_key,
            wrapped_key_algorithm,
            wrapped_key_type,
            additional_associated_data=None
    ):
        # type: (Text, bytes, Text, EncryptionKeyType, Optional[Dict[Text, Text]]) -> DelegatedKey
        # pylint: disable=unused-argument,no-self-use
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to unwrap key
        :param bytes content_key: Raw content key to wrap
        :param str wrapped_key_algorithm: Text description of algorithm for unwrapped key to use
        :param EncryptionKeyType wrapped_key_type: Type of key to treat key as once unwrapped
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on wrap it must be required on unwrap.
        :returns: Delegated key using unwrapped key
        :rtype: DelegatedKey
        """
        _raise_not_implemented('unwrap')

    def sign(self, algorithm, data):  # type: ignore
        # type: (Text, bytes) -> bytes
        # pylint: disable=unused-argument,no-self-use
        """Sign data.

        :param str algorithm: Text description of algorithm to use to sign data
        :param bytes data: Data to sign
        :returns: Signature value
        :rtype: bytes
        """
        _raise_not_implemented('sign')

    def verify(self, algorithm, signature, data):  # type: ignore
        # type: (Text, bytes, bytes) -> None
        # pylint: disable=unused-argument,no-self-use
        """Sign data.

        :param str algorithm: Text description of algorithm to use to verify signature
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        """
        _raise_not_implemented('verify')

    def signing_algorithm(self):  # type: ignore
        # type: () -> Text
        # pylint: disable=no-self-use
        """Provide a description that can inform an appropriate cryptographic materials
        provider about how to build a :class:`DelegatedKey` for signature verification.
        If implemented, the return value of this method is included in the material description
        written to the encrypted item.

        :returns: Signing algorithm identifier
        :rtype: str
        """
        _raise_not_implemented('signing_algorithm')
