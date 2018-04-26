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
"""Delegated key that uses JCE StandardName values to determine behavior."""
from __future__ import division

import logging
import os

import attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Optional, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import JceTransformationError, UnwrappingError
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType, LOGGER_NAME
from dynamodb_encryption_sdk.internal.crypto.jce_bridge import authentication, encryption, primitives
from . import DelegatedKey

__all__ = ('JceNameLocalDelegatedKey',)
_LOGGER = logging.getLogger(LOGGER_NAME)


def _generate_symmetric_key(key_length):
    """Generate a new AES key.

    :param int key_length: Required key length in bits
    :returns: raw key, symmetric key identifier, and RAW encoding identifier
    :rtype: tuple(bytes, :class:`EncryptionKeyType`, :class:`KeyEncodingType`)
    """
    return os.urandom(key_length // 8), EncryptionKeyType.SYMMETRIC, KeyEncodingType.RAW


def _generate_rsa_key(key_length):
    """Generate a new RSA private key.

    :param int key_length: Required key length in bits
    :returns: DER-encoded private key, private key identifier, and DER encoding identifier
    :rtype: tuple(bytes, :class:`EncryptionKeyType`, :class:`KeyEncodingType`)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_length,
        backend=default_backend()
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return key_bytes, EncryptionKeyType.PRIVATE, KeyEncodingType.DER


_ALGORITHM_GENERATE_MAP = {
    'SYMMETRIC': _generate_symmetric_key,
    'RSA': _generate_rsa_key
}


@attr.s(init=False)
class JceNameLocalDelegatedKey(DelegatedKey):
    # pylint: disable=too-many-instance-attributes
    """Delegated key that uses JCE StandardName values to determine behavior.

    Accepted algorithm names for this include:

    * `JCE Mac names`_ (for a signing key)

        * **HmacSHA512**
        * **HmacSHA256**
        * **HmacSHA384**
        * **HmacSHA224**

    * `JCE Signature names`_ (for a signing key)

        * **SHA512withRSA**
        * **SHA256withRSA**
        * **SHA384withRSA**
        * **SHA224withRSA**

    * `JCE Cipher names`_ (for an encryption key)

        * **RSA**
        * **AES**
        * **AESWrap**

    .. _JCE Mac names:
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac
    .. _JCE Signature names:
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
    .. _JCE Cipher names:
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher

    :param bytes key: Raw key bytes
    :param str algorithm: JCE Standard Algorithm Name
    :param EncryptionKeyType key_type: Identifies what type of key is being provided
    :param KeyEncodingType key_encoding: Identifies how the provided key is encoded
    """

    key = attr.ib(validator=attr.validators.instance_of(bytes), repr=False)
    _algorithm = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _key_type = attr.ib(validator=attr.validators.instance_of(EncryptionKeyType))
    _key_encoding = attr.ib(validator=attr.validators.instance_of(KeyEncodingType))

    def __init__(
            self,
            key,  # type: bytes
            algorithm,  # type: Text
            key_type,  # type: EncryptionKeyType
            key_encoding,  # type: KeyEncodingType
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.key = key
        self._algorithm = algorithm
        self._key_type = key_type
        self._key_encoding = key_encoding
        attr.validate(self)
        self.__attrs_post_init__()

    @property
    def algorithm(self):
        # type: () -> Text
        """Text description of algorithm used by this delegated key."""
        return self._algorithm

    def _enable_authentication(self):
        # () -> None
        """Enable authentication methods for keys that support them."""
        self.sign = self._sign
        self.verify = self._verify
        self.signing_algorithm = self._signing_algorithm

    def _enable_encryption(self):
        # () -> None
        """Enable encryption methods for keys that support them."""
        self.encrypt = self._encrypt
        self.decrypt = self._decrypt

    def _enable_wrap(self):
        # () -> None
        """Enable key wrapping methods for keys that support them."""
        self.wrap = self._wrap
        self.unwrap = self._unwrap

    def __attrs_post_init__(self):
        # () -> None
        """Identify the correct key handler class for the requested algorithm and load the provided key."""
        # First try for encryption ciphers
        # https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        try:
            key_transformer = primitives.JAVA_ENCRYPTION_ALGORITHM[self.algorithm]
        except KeyError:
            pass
        else:
            self.__key = key_transformer.load_key(  # attrs confuses pylint: disable=attribute-defined-outside-init
                self.key,
                self._key_type,
                self._key_encoding
            )
            self._enable_encryption()
            self._enable_wrap()
            return

        # Now try for authenticators
        # https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html
        # https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html
        try:
            key_transformer = authentication.JAVA_AUTHENTICATOR[self.algorithm]
        except KeyError:
            pass
        else:
            self.__key = key_transformer.load_key(  # attrs confuses pylint: disable=attribute-defined-outside-init
                self.key,
                self._key_type,
                self._key_encoding
            )
            self._enable_authentication()
            return

        raise JceTransformationError('Unknown algorithm: "{}"'.format(self.algorithm))

    @classmethod
    def generate(cls, algorithm, key_length=None):
        # type: (Text, Optional[int]) -> JceNameLocalDelegatedKey
        """Generate an instance of this :class:`DelegatedKey` using the specified algorithm
        and key length.

        :param str algorithm: Text description of algorithm to be used
        :param int key_length: Size in bits of key to generate
        :returns: Generated delegated key
        :rtype: DelegatedKey
        """
        # Normalize to allow generating both encryption and signing keys
        algorithm_lookup = algorithm.upper()
        if 'HMAC' in algorithm_lookup or algorithm_lookup in ('AES', 'AESWRAP'):
            algorithm_lookup = 'SYMMETRIC'
        elif 'RSA' in algorithm_lookup:
            algorithm_lookup = 'RSA'

        try:
            key_generator = _ALGORITHM_GENERATE_MAP[algorithm_lookup]
        except KeyError:
            raise ValueError('Unknown algorithm: {}'.format(algorithm))

        key, key_type, key_encoding = key_generator(key_length)
        return cls(key=key, algorithm=algorithm, key_type=key_type, key_encoding=key_encoding)

    @property
    def allowed_for_raw_materials(self):
        # type: () -> bool
        """Only :class:`JceNameLocalDelegatedKey` backed by AES keys are allowed to be used
        with :class:`RawDecryptionMaterials` or :class:`RawEncryptionMaterials`.

        :returns: decision
        :rtype: bool
        """
        return self.algorithm == 'AES'

    def _encrypt(self, algorithm, name, plaintext, additional_associated_data=None):
        # type: (Text, Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument
        """
        Encrypt data.

        :param str algorithm: Java StandardName transformation string of algorithm to use to encrypt data
            https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        :param str name: Name associated with plaintext data
        :param bytes plaintext: Plaintext data to encrypt
        :param dict additional_associated_data: Not used by all delegated keys, but if it
            is, then if it is provided on encrypt it must be required on decrypt.
        :returns: Encrypted ciphertext
        :rtype: bytes
        """
        encryptor = encryption.JavaCipher.from_transformation(algorithm)
        return encryptor.encrypt(self.__key, plaintext)

    def _decrypt(self, algorithm, name, ciphertext, additional_associated_data=None):
        # type: (Text, Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument
        """Encrypt data.

        :param str algorithm: Java StandardName transformation string of algorithm to use to decrypt data
            https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        :param str name: Name associated with ciphertext data
        :param bytes ciphertext: Ciphertext data to decrypt
        :param dict additional_associated_data: Not used by :class:`JceNameLocalDelegatedKey`
        :returns: Decrypted plaintext
        :rtype: bytes
        """
        decryptor = encryption.JavaCipher.from_transformation(algorithm)
        return decryptor.decrypt(self.__key, ciphertext)

    def _wrap(self, algorithm, content_key, additional_associated_data=None):
        # type: (Text, bytes, Optional[Dict[Text, Text]]) -> bytes
        # pylint: disable=unused-argument
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to wrap key
        :param bytes content_key: Raw content key to wrap
        :param dict additional_associated_data: Not used by :class:`JceNameLocalDelegatedKey`
        :returns: Wrapped key
        :rtype: bytes
        """
        wrapper = encryption.JavaCipher.from_transformation(algorithm)
        return wrapper.wrap(
            wrapping_key=self.__key,
            key_to_wrap=content_key
        )

    def _unwrap(self, algorithm, wrapped_key, wrapped_key_algorithm, wrapped_key_type, additional_associated_data=None):
        # type: (Text, bytes, Text, EncryptionKeyType, Optional[Dict[Text, Text]]) -> DelegatedKey
        # pylint: disable=unused-argument
        """Wrap content key.

        :param str algorithm: Text description of algorithm to use to unwrap key
        :param bytes content_key: Raw content key to wrap
        :param str wrapped_key_algorithm: Text description of algorithm for unwrapped key to use
        :param EncryptionKeyType wrapped_key_type: Type of key to treat key as once unwrapped
        :param dict additional_associated_data: Not used by :class:`JceNameLocalDelegatedKey`
        :returns: Delegated key using unwrapped key
        :rtype: DelegatedKey
        """
        if wrapped_key_type is not EncryptionKeyType.SYMMETRIC:
            raise UnwrappingError('Unsupported wrapped key type: "{}"'.format(wrapped_key_type))

        unwrapper = encryption.JavaCipher.from_transformation(algorithm)
        unwrapped_key = unwrapper.unwrap(
            wrapping_key=self.__key,
            wrapped_key=wrapped_key
        )
        return JceNameLocalDelegatedKey(
            key=unwrapped_key,
            algorithm=wrapped_key_algorithm,
            key_type=wrapped_key_type,
            key_encoding=KeyEncodingType.RAW
        )

    def _sign(self, algorithm, data):
        # type: (Text, bytes) -> bytes
        """Sign data.

        :param str algorithm: Text description of algorithm to use to sign data
        :param bytes data: Data to sign
        :returns: Signature value
        :rtype: bytes
        """
        signer = authentication.JAVA_AUTHENTICATOR[algorithm]
        return signer.sign(self.__key, data)

    def _verify(self, algorithm, signature, data):
        # type: (Text, bytes, bytes) -> None
        """Sign data.

        :param str algorithm: Text description of algorithm to use to verify signature
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        """
        verifier = authentication.JAVA_AUTHENTICATOR[algorithm]
        verifier.verify(self.__key, signature, data)

    def _signing_algorithm(self):
        # type: () -> Text
        """Provide a description that can inform an appropriate cryptographic materials
        provider about how to build a ``JceNameLocalDelegatedKey`` for signature verification.
        The return value of this method is included in the material description written to
        the encrypted item.

        :returns: Signing algorithm identifier
        :rtype: str
        """
        return self.algorithm
