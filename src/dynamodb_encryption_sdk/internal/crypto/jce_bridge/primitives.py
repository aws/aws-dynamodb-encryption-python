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
"""Cryptographic primitive resources for JCE bridge."""
import abc
import attr
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as symmetric_padding, hashes, serialization, keywrap
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
import six

from dynamodb_encryption_sdk.exceptions import (
    DecryptionError, EncryptionError, InvalidAlgorithmError, UnwrappingError, WrappingError
)
from dynamodb_encryption_sdk.identifiers import EncryptionKeyTypes, KeyEncodingType, LOGGER_NAME

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
    """Bridge the gap from the Java padding names and Python resources.
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """

    @abc.abstractmethod
    def build(self, block_size):
        """Build an instance of this padding type."""


@attr.s
class SimplePadding(JavaPadding):
    """Padding types that do not require any preparation."""
    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib()

    def build(self, block_size=None):
        # type: (int) -> ANY
        """Build an instance of this padding type.

        :param int block_size: Not used by SimplePadding. Ignored and not required.
        :returns: Padding instance
        """
        return self.padding()


@attr.s
class BlockSizePadding(JavaPadding):
    """Padding types that require a block size input."""
    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib()

    def build(self, block_size):
        # type: (int) -> ANY
        """Build an instance of this padding type.

        :param int block_size: Block size of algorithm for which to build padder.
        :returns: Padding instance
        """
        return self.padding(block_size)


@attr.s
class OaepPadding(JavaPadding):
    """OAEP padding types. These require more complex setup.

    .. warning::

        By default, Java incorrectly implements RSA OAEP for all hash functions besides SHA1.
        The same hashing algorithm should be used by both OAEP and the MGF, but by default
        Java always uses SHA1 for the MGF.
    """
    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding = attr.ib()
    digest = attr.ib()
    mgf = attr.ib()
    mgf_digest = attr.ib()

    def build(self, block_size=None):
        # type: (int) -> ANY
        """Build an instance of this padding type.

        :param int block_size: Not used by OaepPadding. Ignored and not required.
        :returns: Padding instance
        """
        return self.padding(
            mgf=self.mgf(algorithm=self.mgf_digest()),
            algorithm=self.digest(),
            label=None
        )


@attr.s
class JavaMode(object):
    """Bridge the gap from the Java encryption mode names and Python resources.
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """
    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    mode = attr.ib()

    def build(self, iv):
        # type: (int) -> ANY
        """Build an instance of this mode type.

        :param bytes iv: Initialization vector bytes
        :returns: Mode instance
        """
        return self.mode(iv)


@attr.s
class JavaEncryptionAlgorithm(object):
    """Bridge the gap from the Java encryption algorithm names and Python resources.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
    """
    java_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    cipher = attr.ib()

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
        :param key_type: Type of key
        :type key_type: dynamodb_encryption_sdk.identifiers.EncryptionKeyTypes
        :param key_encoding: Encoding used to serialize key
        :type key_encoding: dynamodb_encryption_sdk.identifiers.KeyEncodingType
        :returns: Loaded key
        """
        if key_type is not EncryptionKeyTypes.SYMMETRIC:
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
        """Encrypt data using the supplied values.

        :param bytes key: Loaded encryption key
        :param bytes data: Data to encrypt
        :param mode: Encryption mode to use
        :type mode: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaMode
        :param padding: Padding mode to use
        :type padding: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaPadding
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
        """Decrypt data using the supplied values.

        :param bytes key: Loaded decryption key
        :param bytes data: IV prepended to encrypted data
        :param mode: Decryption mode to use
        :type mode: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaMode
        :param padding: Padding mode to use
        :type padding: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaPadding
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
    EncryptionKeyTypes.PRIVATE: {
        KeyEncodingType.DER: serialization.load_der_private_key,
        KeyEncodingType.PEM: serialization.load_pem_private_key
    },
    EncryptionKeyTypes.PUBLIC: {
        KeyEncodingType.DER: serialization.load_der_public_key,
        KeyEncodingType.PEM: serialization.load_pem_public_key
    }
}


def load_rsa_key(key, key_type, key_encoding):
    """"""
    try:
        loader = _RSA_KEY_LOADING[key_type][key_encoding]
    except KeyError:
        raise Exception('Invalid key type: {}'.format(key_type))

    kwargs = dict(data=key, backend=default_backend())
    if key_type is EncryptionKeyTypes.PRIVATE:
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
        :param key_type: Type of key
        :type key_type: dynamodb_encryption_sdk.identifiers.EncryptionKeyTypes
        :param key_encoding: Encoding used to serialize key
        :type key_encoding: dynamodb_encryption_sdk.identifiers.KeyEncodingType
        :returns: Loaded key
        """
        if key_type not in (EncryptionKeyTypes.PRIVATE, EncryptionKeyTypes.PUBLIC):
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
        """Encrypt data using the supplied values.

        :param bytes key: Loaded encryption key
        :param bytes data: Data to encrypt
        :param mode: Encryption mode to use (not used by ``JavaAsymmetricEncryptionAlgorithm``)
        :type mode: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaMode
        :param padding: Padding mode to use
        :type padding: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaPadding
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
        """Decrypt data using the supplied values.

        :param bytes key: Loaded decryption key
        :param bytes data: IV prepended to encrypted data
        :param mode: Decryption mode to use (not used by ``JavaAsymmetricEncryptionAlgorithm``)
        :type mode: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaMode
        :param padding: Padding mode to use
        :type padding: dynamodb_encryption_sdk.internal.crypto.jce_bridge.primitives.JavaPadding
        :returns: Decrypted data
        :rtype: bytes
        """
        if hasattr(key, 'public_bytes'):
            raise NotImplementedError('TODO:"decrypt" is not supported by public keys')
        try:
            return key.decrypt(data, padding.build())
        except Exception:
            error_message = 'Decryption failed'
            _LOGGER.exception(error_message)
            raise DecryptionError(error_message)


JAVA_ENCRYPTION_ALGORITHM = {
    'RSA': JavaAsymmetricEncryptionAlgorithm('RSA', rsa),
    'AES': JavaSymmetricEncryptionAlgorithm('AES', algorithms.AES),
    'AESWrap': JavaSymmetricEncryptionAlgorithm('AESWrap', algorithms.AES)
    # TODO: Should we support these?
    # DES : pretty sure we don't want to support this
    # DESede : pretty sure we don't want to support this
    # 'BLOWFISH': JavaSymmetricEncryptionAlgorithm('Blowfish', algorithms.Blowfish)
}
JAVA_MODE = {
    'ECB': JavaMode('ECB', modes.ECB),
    'CBC': JavaMode('CBC', modes.CBC),
    'CTR': JavaMode('CTR', modes.CTR),
    'GCM': JavaMode('GCM', modes.GCM)
    # TODO: Should we support these?
    # 'OFB': JavaMode('OFB', modes.OFB)
    # 'CFB': JavaMode('CFB', modes.CFB)
    # 'CFB8': JavaMode('CFB8', modes.CFB8)
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
