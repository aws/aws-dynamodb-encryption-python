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
    from typing import Dict, Text  # pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

import six

from dynamodb_encryption_sdk.identifiers import EncryptionKeyTypes


@six.add_metaclass(abc.ABCMeta)
class DelegatedKey(object):
    """Delegated keys are black boxes that encrypt, decrypt, sign, and verify data and wrap
    and unwrap keys. Not all delegated keys implement all methods.

    Unless overridden by a subclass, any method that a delegated key does not implement raises
    a ``NotImplementedError`` detailing this.
    """
    #: Most delegated keys should not be used with RawCryptographicMaterials.
    allowed_for_raw_materials = False

    @abc.abstractproperty
    def algorithm(self):
        # type: () -> Text
        """Text description of algorithm used by this delegated key."""

    def _raise_not_implemented(self, method_name):
        """Raises a standardized ``NotImplementedError`` to report that the specified method
        is not supported.

        :raises NotImplementedError: when called
        """
        raise NotImplementedError('"{}" is not supported by this DelegatedKey'.format(method_name))

    @classmethod
    def generate(cls, algorithm, key_length):
        """Generate an instance of this DelegatedKey using the specified algorithm and key length.

        :param str algorithm: Text description of algorithm to be used
        :param int key_length: Size of key to generate
        :returns: Generated delegated key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        cls._raise_not_implemented('generate')

    def encrypt(self, algorithm, name, plaintext, additional_associated_data=None):
        # type: (Text, Text, bytes, Dict[Text, Text]) -> bytes
        """Encrypt data.

        :param str algorithm: Text description of algorithm to use to encrypt data
        :param str name: Name associated with plaintext data
        :param bytes plaintext: Plaintext data to encrypt
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on encrypt it must be required on decrypt.
        :returns: Encrypted ciphertext
        :rtype: bytes
        """
        self._raise_not_implemented('encrypt')

    def decrypt(self, algorithm, name, ciphertext, additional_associated_data=None):
        # type: (Text, Text, bytes, Dict[Text, Text]) -> bytes
        """Encrypt data.

        :param str algorithm: Text description of algorithm to use to decrypt data
        :param str name: Name associated with ciphertext data
        :param bytes ciphertext: Ciphertext data to decrypt
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on encrypt it must be required on decrypt.
        :returns: Decrypted plaintext
        :rtype: bytes
        """
        self._raise_not_implemented('decrypt')

    def wrap(self, algorithm, content_key, additional_associated_data=None):
        # type: (Text, bytes, Dict[Text, Text]) -> bytes
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to wrap key
        :param bytes content_key: Raw content key to wrap
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on wrap it must be required on unwrap.
        :returns: Wrapped key
        :rtype: bytes
        """
        self._raise_not_implemented('wrap')

    def unwrap(self, algorithm, wrapped_key, wrapped_key_algorithm, wrapped_key_type, additional_associated_data=None):
        # type: (Text, bytes, Text, EncryptionKeyTypes, Dict[Text, Text]) -> DelegatedKey
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to unwrap key
        :param bytes content_key: Raw content key to wrap
        :param str wrapped_key_algorithm: Text description of algorithm for unwrapped key to use
        :param wrapped_key_type: Type of key to treat key as once unwrapped
        :type wrapped_key_type: dynamodb_encryption_sdk.identifiers.EncryptionKeyTypes
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on wrap it must be required on unwrap.
        :returns: Delegated key using unwrapped key
        :rtype: dynamodb_encryption_sdk.delegated_keys.DelegatedKey
        """
        self._raise_not_implemented('unwrap')

    def sign(self, algorithm, data):
        # type: (Text, bytes) -> bytes
        """Sign data.

        :param str algorithm: Text description of algorithm to use to sign data
        :param bytes data: Data to sign
        :returns: Signature value
        :rtype: bytes
        """
        self._raise_not_implemented('sign')

    def verify(self, algorithm, signature, data):
        # type: (Text, bytes, bytes) -> None
        """Sign data.

        :param str algorithm: Text description of algorithm to use to verify signature
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        """
        self._raise_not_implemented('verify')

    def signing_algorithm(self):
        # type: () -> Text
        """Provides a description that can inform an appropriate cryptographic materials
        provider about how to build a DelegatedKey for signature verification. If implemented,
        the return value of this method is included in the material description written to
        the encrypted item.

        :returns: Signing algorithm identifier
        :rtype: str
        """
        self._raise_not_implemented('signing_algorithm')
