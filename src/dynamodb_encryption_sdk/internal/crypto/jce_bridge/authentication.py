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
"""Cryptographic authentication resources for JCE bridge.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import abc
import logging

import attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Callable, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import InvalidAlgorithmError, SignatureVerificationError, SigningError
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType, LOGGER_NAME
from dynamodb_encryption_sdk.internal.validators import callable_validator
from .primitives import load_rsa_key

__all__ = ('JavaAuthenticator', 'JavaMac', 'JavaSignature', 'JAVA_AUTHENTICATOR')
_LOGGER = logging.getLogger(LOGGER_NAME)


@six.add_metaclass(abc.ABCMeta)
class JavaAuthenticator(object):
    """Parent class for all Java bridges that provide authentication characteristics."""

    @abc.abstractmethod
    def load_key(self, key, key_type, key_encoding):
        # (bytes, EncryptionKeyType, KeyEncodingType) -> Any
        # TODO: narrow down the output type
        """Load a key from bytes.

        :param bytes key: Raw key bytes to load
        :param EncryptionKeyType key_type: Type of key to load
        :param KeyEncodingType key_encoding: Encoding used to serialize ``key``
        :returns: Loaded key
        :rtype: bytes
        """

    @abc.abstractmethod
    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this authenticator.

        :param str algorithm: Algorithm name
        :raises InvalidAlgorithmError: if specified algorithm name is not compatible with this authenticator
        """

    @abc.abstractmethod
    def sign(self, key, data):
        # type: (Any, bytes) -> bytes
        """Sign ``data`` using loaded ``key``.

        :param key: Loaded key
        :param bytes data: Data to sign
        :returns: Calculated signature
        :rtype: bytes
        :raises SigningError: if unable to sign ``data`` with ``key``
        """

    @abc.abstractmethod
    def verify(self, key, signature, data):
        # type: (Any, bytes, bytes) -> None
        """Verify ``signature`` over ``data`` using ``key``.

        :param key: Loaded key
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        :raises SignatureVerificationError: if unable to verify ``signature``
        """


@attr.s(init=False)
class JavaMac(JavaAuthenticator):
    """Symmetric MAC authenticators.

    https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac
    """

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    algorithm_type = attr.ib(validator=callable_validator)
    hash_type = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            algorithm_type,  # type: Callable
            hash_type  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.algorithm_type = algorithm_type
        self.hash_type = hash_type
        attr.validate(self)

    def _build_hmac_signer(self, key):
        # type: (bytes) -> Any
        """Build HMAC signer using instance algorithm and hash type and ``key``.

        :param bytes key: Key to use in signer
        """
        return self.algorithm_type(
            key,
            self.hash_type(),
            backend=default_backend()
        )

    def load_key(self, key, key_type, key_encoding):
        # (bytes, EncryptionKeyType, KeyEncodingType) -> bytes
        """Load a raw key from bytes.

        :param bytes key: Raw key bytes to load
        :param EncryptionKeyType key_type: Type of key to load
        :param KeyEncodingType key_encoding: Encoding used to serialize ``key``
        :returns: Loaded key
        :rtype: bytes
        :raises ValueError: if ``key_type`` is not symmetric or ``key_encoding`` is not raw
        """
        if not (key_type is EncryptionKeyType.SYMMETRIC and key_encoding is KeyEncodingType.RAW):
            raise ValueError('Key type must be symmetric and encoding must be raw.')

        return key

    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this authenticator.

        :param str algorithm: Algorithm name
        :raises InvalidAlgorithmError: if specified algorithm name is not compatible with this authenticator
        """
        if not algorithm.startswith(self.java_name):
            raise InvalidAlgorithmError(
                'Requested algorithm "{requested}" is not compatible with signature "{actual}"'.format(
                    requested=algorithm,
                    actual=self.java_name
                )
            )

    def sign(self, key, data):
        # type: (bytes, bytes) -> bytes
        """Sign ``data`` using loaded ``key``.

        :param bytes key: Loaded key
        :param bytes data: Data to sign
        :returns: Calculated signature
        :rtype: bytes
        :raises SigningError: if unable to sign ``data`` with ``key``
        """
        try:
            signer = self._build_hmac_signer(key)
            signer.update(data)
            return signer.finalize()
        except Exception:
            message = 'Unable to sign data'
            _LOGGER.exception(message)
            raise SigningError(message)

    def verify(self, key, signature, data):
        # type: (bytes, bytes, bytes) -> None
        """Verify ``signature`` over ``data`` using ``key``.

        :param bytes key: Loaded key
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        :raises SignatureVerificationError: if unable to verify ``signature``
        """
        try:
            verifier = self._build_hmac_signer(key)
            verifier.update(data)
            verifier.verify(signature)
        except Exception:
            message = 'Unable to verify signature'
            _LOGGER.exception(message)
            raise SignatureVerificationError(message)


@attr.s(init=False)
class JavaSignature(JavaAuthenticator):
    """Asymmetric signature authenticators.

    https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
    """

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    algorithm_type = attr.ib()
    hash_type = attr.ib(validator=callable_validator)
    padding_type = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            algorithm_type,
            hash_type,  # type: Callable
            padding_type  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.algorithm_type = algorithm_type
        self.hash_type = hash_type
        self.padding_type = padding_type
        attr.validate(self)

    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this authenticator.

        :param str algorithm: Algorithm name
        :raises InvalidAlgorithmError: if specified algorithm name is not compatible with this authenticator
        """
        if not algorithm.endswith(self.java_name):
            raise InvalidAlgorithmError(
                'Requested algorithm "{requested}" is not compatible with signature "{actual}"'.format(
                    requested=algorithm,
                    actual=self.java_name
                )
            )

    def load_key(self, key, key_type, key_encoding):
        # (bytes, EncryptionKeyType, KeyEncodingType) -> Any
        # TODO: narrow down the output type
        """Load a key object from the provided raw key bytes.

        :param bytes key: Raw key bytes to load
        :param EncryptionKeyType key_type: Type of key to load
        :param KeyEncodingType key_encoding: Encoding used to serialize ``key``
        :returns: Loaded key
        :rtype: TODO:
        :raises ValueError: if ``key_type`` and ``key_encoding`` are not a valid pairing
        """
        return load_rsa_key(key, key_type, key_encoding)

    def sign(self, key, data):
        # type: (Any, bytes) -> bytes
        # TODO: narrow down the key type
        """Sign ``data`` using loaded ``key``.

        :param key: Loaded key
        :type key: TODO:
        :param bytes data: Data to sign
        :returns: Calculated signature
        :rtype: bytes
        :raises SigningError: if unable to sign ``data`` with ``key``
        """
        if hasattr(key, 'public_bytes'):
            raise SigningError('"sign" is not supported by public keys')
        try:
            return key.sign(
                data,
                self.padding_type(),
                self.hash_type()
            )
        except Exception:
            message = 'Unable to sign data'
            _LOGGER.exception(message)
            raise SigningError(message)

    def verify(self, key, signature, data):
        # type: (Any, bytes, bytes) -> None
        # TODO: narrow down the key type
        """Verify ``signature`` over ``data`` using ``key``.

        :param key: Loaded key
        :type key: TODO:
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        :raises SignatureVerificationError: if unable to verify ``signature``
        """
        if hasattr(key, 'private_bytes'):
            _key = key.public_key()
        else:
            _key = key
        try:
            _key.verify(
                signature,
                data,
                self.padding_type(),
                self.hash_type()
            )
        except Exception:
            message = 'Unable to verify signature'
            _LOGGER.exception(message)
            raise SignatureVerificationError(message)


# Additional possible JCE names that we might support in the future if needed
# HmacSHA1
# SHA(1|224|256|384|512)with(|EC)DSA
# If this changes, remember to update the JceNameLocalDelegatedKey docs.
JAVA_AUTHENTICATOR = {
    'HmacSHA224': JavaMac('HmacSHA224', hmac.HMAC, hashes.SHA224),
    'HmacSHA256': JavaMac('HmacSHA256', hmac.HMAC, hashes.SHA256),
    'HmacSHA384': JavaMac('HmacSHA384', hmac.HMAC, hashes.SHA384),
    'HmacSHA512': JavaMac('HmacSHA512', hmac.HMAC, hashes.SHA512),
    'SHA224withRSA': JavaSignature('SHA224withRSA', rsa, hashes.SHA224, padding.PKCS1v15),
    'SHA256withRSA': JavaSignature('SHA256withRSA', rsa, hashes.SHA256, padding.PKCS1v15),
    'SHA384withRSA': JavaSignature('SHA384withRSA', rsa, hashes.SHA384, padding.PKCS1v15),
    'SHA512withRSA': JavaSignature('SHA512withRSA', rsa, hashes.SHA512, padding.PKCS1v15)
}
