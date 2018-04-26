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
"""Cryptographic primitive resources for JCE bridge.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import abc
import logging
import os

import attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, keywrap, padding as symmetric_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Callable, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import (
    DecryptionError, EncryptionError, InvalidAlgorithmError, UnwrappingError, WrappingError
)
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType, LOGGER_NAME
from dynamodb_encryption_sdk.internal.validators import callable_validator

__all__ = (
    'JavaPadding', 'SimplePadding', 'BlockSizePadding', 'OaepPadding',
    'JavaMode',
    'JavaEncryptionAlgorithm', 'JavaSymmetricEncryptionAlgorithm', 'JavaAsymmetricEncryptionAlgorithm',
    'JAVA_ENCRYPTION_ALGORITHM', 'JAVA_MODE', 'JAVA_PADDING'
)
_LOGGER = logging.getLogger(LOGGER_NAME)


class _NoPadding(object):
    """Provide NoPadding padding object."""

    class _NoPadder(symmetric_padding.PaddingContext):
        """Provide padder/unpadder functionality for NoPadding."""

        def update(self, data):
            """Directly return the input data cast to bytes.

            :param bytes data: Data to (not) pad/unpad
            :returns: (Not) padded/unpadded data
            :rtype: bytes
            """
            return data

        def finalize(self):
            """Provide the finalize interface but returns an empty bytestring.

            :returns: Empty bytestring
            :rtype: bytes
            """
            return b''

    def padder(self):
        """Return NoPadder object.

        :returns: NoPadder object.
        :rtype: _NoPadder
        """
        return self._NoPadder()

    def unpadder(self):
        """Return NoPadder object.

        :returns: NoPadder object.
        :rtype: _NoPadder
        """
        return self._NoPadder()


@six.add_metaclass(abc.ABCMeta)
class JavaPadding(object):
    # pylint: disable=too-few-public-methods
    """Bridge the gap from the Java padding names and Python resources.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    @abc.abstractmethod
    def build(self, block_size):
        """Build an instance of this padding type."""


@attr.s(init=False)
class SimplePadding(JavaPadding):
    # pylint: disable=too-few-public-methods
    """Padding types that do not require any preparation."""

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            padding  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.padding = padding
        attr.validate(self)

    def build(self, block_size=None):
        # type: (int) -> Any
        """Build an instance of this padding type.

        :param int block_size: Not used by SimplePadding. Ignored and not required.
        :returns: Padding instance
        """
        return self.padding()


@attr.s(init=False)
class BlockSizePadding(JavaPadding):
    # pylint: disable=too-few-public-methods
    """Padding types that require a block size input."""

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            padding  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.padding = padding
        attr.validate(self)

    def build(self, block_size):
        # type: (int) -> Any
        """Build an instance of this padding type.

        :param int block_size: Block size of algorithm for which to build padder.
        :returns: Padding instance
        """
        return self.padding(block_size)


@attr.s(init=False)
class OaepPadding(JavaPadding):
    # pylint: disable=too-few-public-methods
    """OAEP padding types. These require more complex setup.

    .. warning::

        By default, Java incorrectly implements RSA OAEP for all hash functions besides SHA1.
        The same hashing algorithm should be used by both OAEP and the MGF, but by default
        Java always uses SHA1 for the MGF.

        Because we need to match this behavior, all :class:`OaepPadding` instances should be
        created with MGF1-SHA1.
    """

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib(validator=callable_validator)
    digest = attr.ib(validator=callable_validator)
    mgf = attr.ib(validator=callable_validator)
    mgf_digest = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            padding,  # type: Callable
            digest,  # type: Callable
            mgf,  # type: Callable
            mgf_digest  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.padding = padding
        self.digest = digest
        self.mgf = mgf
        self.mgf_digest = mgf_digest
        attr.validate(self)

    def build(self, block_size=None):
        # type: (int) -> Any
        """Build an instance of this padding type.

        :param int block_size: Not used by OaepPadding. Ignored and not required.
        :returns: Padding instance
        """
        return self.padding(
            mgf=self.mgf(algorithm=self.mgf_digest()),
            algorithm=self.digest(),
            label=None
        )


@attr.s(init=False)
class JavaMode(object):
    # pylint: disable=too-few-public-methods
    """Bridge the gap from the Java encryption mode names and Python resources.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    mode = attr.ib(validator=callable_validator)

    def __init__(
            self,
            java_name,  # type: Text
            mode  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.mode = mode
        attr.validate(self)

    def build(self, iv):
        # type: (int) -> Any
        """Build an instance of this mode type.

        :param bytes iv: Initialization vector bytes
        :returns: Mode instance
        """
        return self.mode(iv)


@attr.s(init=False)
class JavaEncryptionAlgorithm(object):
    # pylint: disable=too-few-public-methods
    """Bridge the gap from the Java encryption algorithm names and Python resources.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    cipher = attr.ib()

    def __init__(
            self,
            java_name,  # type: Text
            cipher  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.java_name = java_name
        self.cipher = cipher
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        """No-op stub to standardize API."""

    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this cipher"""
        if not algorithm == self.java_name:
            raise InvalidAlgorithmError(
                'Requested algorithm "{requested}" is not compatible with cipher "{actual}"'.format(
                    requested=algorithm,
                    actual=self.java_name
                )
            )


class JavaSymmetricEncryptionAlgorithm(JavaEncryptionAlgorithm):
    """JavaEncryptionAlgorithm for symmetric algorithms.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    def _disabled_encrypt(self, *args, **kwargs):
        """Catcher for algorithms that do not support encryption."""
        raise NotImplementedError('"encrypt" is not supported by the "{}" algorithm'.format(self.java_name))

    def _disabled_decrypt(self, *args, **kwargs):
        """Catcher for algorithms that do not support decryption."""
        raise NotImplementedError('"decrypt" is not supported by the "{}" algorithm'.format(self.java_name))

    def _disable_encryption(self):
        # () -> None
        """Enable encryption methods for ciphers that support them."""
        self.encrypt = self._disabled_encrypt
        self.decrypt = self._disabled_decrypt

    def __attrs_post_init__(self):
        # () -> None
        """Disable encryption if algorithm is AESWrap."""
        if self.java_name == 'AESWrap':
            self._disable_encryption()

    def load_key(self, key, key_type, key_encoding):
        """Load a key from bytes.

        :param bytes key: Key bytes
        :param EncryptionKeyType key_type: Type of key
        :param KeyEncodingType key_encoding: Encoding used to serialize key
        :returns: Loaded key
        """
        if key_type is not EncryptionKeyType.SYMMETRIC:
            raise ValueError('Invalid key type "{key_type}" for cipher "{cipher}"'.format(
                key_type=key_type,
                cipher=self.java_name
            ))

        if key_encoding is not KeyEncodingType.RAW:
            raise ValueError('Invalid key encoding "{key_encoding}" for cipher "{cipher}"'.format(
                key_encoding=key_encoding,
                cipher=self.java_name
            ))

        return key

    def wrap(self, wrapping_key, key_to_wrap):
        # type: (bytes, bytes) -> bytes
        """Wrap key using AES keywrap.

        :param bytes wrapping_key: Loaded key with which to wrap
        :param bytes key_to_wrap: Raw key to wrap
        :returns: Wrapped key
        :rtype: bytes
        """
        if self.java_name not in ('AES', 'AESWrap'):
            raise NotImplementedError('"wrap" is not supported by the "{}" cipher'.format(self.java_name))

        try:
            return keywrap.aes_key_wrap(
                wrapping_key=wrapping_key,
                key_to_wrap=key_to_wrap,
                backend=default_backend()
            )
        except Exception:
            error_message = 'Key wrap failed'
            _LOGGER.exception(error_message)
            raise WrappingError(error_message)

    def unwrap(self, wrapping_key, wrapped_key):
        # type: (bytes, bytes) -> bytes
        """Unwrap key using AES keywrap.

        :param bytes wrapping_key: Loaded key with which to unwrap
        :param bytes wrapped_key: Wrapped key to unwrap
        :returns: Unwrapped key
        :rtype: bytes
        """
        if self.java_name not in ('AES', 'AESWrap'):
            raise NotImplementedError('"unwrap" is not supported by this cipher')

        try:
            return keywrap.aes_key_unwrap(
                wrapping_key=wrapping_key,
                wrapped_key=wrapped_key,
                backend=default_backend()
            )
        except Exception:
            error_message = 'Key unwrap failed'
            _LOGGER.exception(error_message)
            raise UnwrappingError(error_message)

    def encrypt(self, key, data, mode, padding):
        # this can be disabled by _disable_encryption, so pylint: disable=method-hidden
        """Encrypt data using the supplied values.

        :param bytes key: Loaded encryption key
        :param bytes data: Data to encrypt
        :param JavaMode mode: Encryption mode to use
        :param JavaPadding padding: Padding mode to use
        :returns: IV prepended to encrypted data
        :rtype: bytes
        """
        try:
            block_size = self.cipher.block_size
            iv_len = block_size // 8
            iv = os.urandom(iv_len)

            encryptor = Cipher(
                self.cipher(key),
                mode.build(iv),
                backend=default_backend()
            ).encryptor()
            padder = padding.build(block_size).padder()

            padded_data = padder.update(data) + padder.finalize()
            return iv + encryptor.update(padded_data) + encryptor.finalize()
        except Exception:
            error_message = 'Encryption failed'
            _LOGGER.exception(error_message)
            raise EncryptionError(error_message)

    def decrypt(self, key, data, mode, padding):
        # this can be disabled by _disable_encryption, so pylint: disable=method-hidden
        """Decrypt data using the supplied values.

        :param bytes key: Loaded decryption key
        :param bytes data: IV prepended to encrypted data
        :param JavaMode mode: Decryption mode to use
        :param JavaPadding padding: Padding mode to use
        :returns: Decrypted data
        :rtype: bytes
        """
        try:
            block_size = self.cipher.block_size
            iv_len = block_size // 8
            iv = data[:iv_len]
            data = data[iv_len:]

            decryptor = Cipher(
                self.cipher(key),
                mode.build(iv),
                backend=default_backend()
            ).decryptor()
            decrypted_data = decryptor.update(data) + decryptor.finalize()

            unpadder = padding.build(block_size).unpadder()
            return unpadder.update(decrypted_data) + unpadder.finalize()
        except Exception:
            error_message = 'Decryption failed'
            _LOGGER.exception(error_message)
            raise DecryptionError(error_message)


_RSA_KEY_LOADING = {
    EncryptionKeyType.PRIVATE: {
        KeyEncodingType.DER: serialization.load_der_private_key,
        KeyEncodingType.PEM: serialization.load_pem_private_key
    },
    EncryptionKeyType.PUBLIC: {
        KeyEncodingType.DER: serialization.load_der_public_key,
        KeyEncodingType.PEM: serialization.load_pem_public_key
    }
}


def load_rsa_key(key, key_type, key_encoding):
    # (bytes, EncryptionKeyType, KeyEncodingType) -> Any
    # TODO: narrow down the output type
    """Load an RSA key object from the provided raw key bytes.

    :param bytes key: Raw key bytes to load
    :param EncryptionKeyType key_type: Type of key to load
    :param KeyEncodingType key_encoding: Encoding used to serialize ``key``
    :returns: Loaded key
    :rtype: TODO:
    :raises ValueError: if ``key_type`` and ``key_encoding`` are not a valid pairing
    """
    try:
        loader = _RSA_KEY_LOADING[key_type][key_encoding]
    except KeyError:
        raise ValueError('Invalid key type and encoding: {} and {}'.format(key_type, key_encoding))

    kwargs = dict(data=key, backend=default_backend())
    if key_type is EncryptionKeyType.PRIVATE:
        kwargs['password'] = None

    return loader(**kwargs)


_KEY_LOADERS = {
    rsa: load_rsa_key
}


class JavaAsymmetricEncryptionAlgorithm(JavaEncryptionAlgorithm):
    """JavaEncryptionAlgorithm for asymmetric algorithms.

    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    def load_key(self, key, key_type, key_encoding):
        """Load a key from bytes.

        :param bytes key: Key bytes
        :param EncryptionKeyType key_type: Type of key
        :param KeyEncodingType key_encoding: Encoding used to serialize key
        :returns: Loaded key
        """
        if key_type not in (EncryptionKeyType.PRIVATE, EncryptionKeyType.PUBLIC):
            raise ValueError('Invalid key type "{key_type}" for cipher "{cipher}"'.format(
                key_type=key_type,
                cipher=self.java_name
            ))

        if key_encoding not in (KeyEncodingType.DER, KeyEncodingType.PEM):
            raise ValueError('Invalid key encoding "{key_encoding}" for cipher "{cipher}"'.format(
                key_encoding=key_encoding,
                cipher=self.java_name
            ))

        return _KEY_LOADERS[self.cipher](key, key_type, key_encoding)

    def encrypt(self, key, data, mode, padding):
        # pylint: disable=unused-argument,no-self-use
        """Encrypt data using the supplied values.

        :param bytes key: Loaded encryption key
        :param bytes data: Data to encrypt
        :param JavaMode mode: Encryption mode to use (not used by :class:`JavaAsymmetricEncryptionAlgorithm`)
        :param JavaPadding padding: Padding mode to use
        :returns: Encrypted data
        :rtype: bytes
        """
        if hasattr(key, 'private_bytes'):
            _key = key.public_key()
        else:
            _key = key
        try:
            return _key.encrypt(data, padding.build())
        except Exception:
            error_message = 'Encryption failed'
            _LOGGER.exception(error_message)
            raise EncryptionError(error_message)

    def decrypt(self, key, data, mode, padding):
        # pylint: disable=unused-argument,no-self-use
        """Decrypt data using the supplied values.

        :param bytes key: Loaded decryption key
        :param bytes data: IV prepended to encrypted data
        :param JavaMode mode: Decryption mode to use (not used by :class:`JavaAsymmetricEncryptionAlgorithm`)
        :param JavaPadding padding: Padding mode to use
        :returns: Decrypted data
        :rtype: bytes
        """
        if hasattr(key, 'public_bytes'):
            raise NotImplementedError('"decrypt" is not supported by public keys')
        try:
            return key.decrypt(data, padding.build())
        except Exception:
            error_message = 'Decryption failed'
            _LOGGER.exception(error_message)
            raise DecryptionError(error_message)


# If this changes, remember to update the JceNameLocalDelegatedKey docs.
JAVA_ENCRYPTION_ALGORITHM = {
    'RSA': JavaAsymmetricEncryptionAlgorithm('RSA', rsa),
    'AES': JavaSymmetricEncryptionAlgorithm('AES', algorithms.AES),
    'AESWrap': JavaSymmetricEncryptionAlgorithm('AESWrap', algorithms.AES)
}
JAVA_MODE = {
    'ECB': JavaMode('ECB', modes.ECB),
    'CBC': JavaMode('CBC', modes.CBC),
    'CTR': JavaMode('CTR', modes.CTR),
    'GCM': JavaMode('GCM', modes.GCM)
}
JAVA_PADDING = {
    'NoPadding': SimplePadding('NoPadding', _NoPadding),
    'PKCS1Padding': SimplePadding('PKCS1Padding', asymmetric_padding.PKCS1v15),
    # PKCS7 padding is a generalization of PKCS5 padding.
    'PKCS5Padding': BlockSizePadding('PKCS5Padding', symmetric_padding.PKCS7),
    # By default, Java incorrectly implements RSA OAEP for all hash functions besides SHA1.
    # The same hashing algorithm should be used by both OAEP and the MGF, but by default
    # Java always uses SHA1 for the MGF.
    'OAEPWithSHA-1AndMGF1Padding': OaepPadding(
        'OAEPWithSHA-1AndMGF1Padding', asymmetric_padding.OAEP, hashes.SHA1, asymmetric_padding.MGF1, hashes.SHA1
    ),
    'OAEPWithSHA-256AndMGF1Padding': OaepPadding(
        'OAEPWithSHA-256AndMGF1Padding', asymmetric_padding.OAEP, hashes.SHA256, asymmetric_padding.MGF1, hashes.SHA1
    ),
    'OAEPWithSHA-384AndMGF1Padding': OaepPadding(
        'OAEPWithSHA-384AndMGF1Padding', asymmetric_padding.OAEP, hashes.SHA384, asymmetric_padding.MGF1, hashes.SHA1
    ),
    'OAEPWithSHA-512AndMGF1Padding': OaepPadding(
        'OAEPWithSHA-512AndMGF1Padding', asymmetric_padding.OAEP, hashes.SHA512, asymmetric_padding.MGF1, hashes.SHA1
    )
}
