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
"""Cipher resource for JCE bridge.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import attr

from dynamodb_encryption_sdk.exceptions import JceTransformationError
from .primitives import (
    JAVA_ENCRYPTION_ALGORITHM, JAVA_MODE, JAVA_PADDING, JavaEncryptionAlgorithm, JavaMode, JavaPadding
)

__all__ = ('JavaCipher',)


@attr.s(init=False)
class JavaCipher(object):
    """Defines the encryption cipher, mode, and padding type to use for encryption.

    https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

    :param JavaEncryptionAlgorithm cipher: Encryption algorithm to use
    :param JavaMode mode: Encryption mode to use
    :param JavaPadding padding: Encryption padding to use
    """

    cipher = attr.ib(validator=attr.validators.instance_of(JavaEncryptionAlgorithm))
    mode = attr.ib(validator=attr.validators.instance_of(JavaMode))
    padding = attr.ib(validator=attr.validators.instance_of(JavaPadding))

    def __init__(
            self,
            cipher,  # type: JavaEncryptionAlgorithm
            mode,  # type: JavaMode
            padding  # type: JavaPadding
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.cipher = cipher
        self.mode = mode
        self.padding = padding
        attr.validate(self)

    def encrypt(self, key, data):
        """Encrypt data using loaded key.

        :param key: Key loaded by ``cipher``
        :param bytes data: Data to encrypt
        :returns: Encrypted data
        :rtype: bytes
        """
        return self.cipher.encrypt(key, data, self.mode, self.padding)

    def decrypt(self, key, data):
        """Decrypt data using loaded key.

        :param key: Key loaded by ``cipher``
        :param bytes data: Data to decrypt
        :returns: Decrypted data
        :rtype: bytes
        """
        return self.cipher.decrypt(key, data, self.mode, self.padding)

    def wrap(self, wrapping_key, key_to_wrap):
        """Wrap key using loaded key.

        :param wrapping_key: Key loaded by ``cipher``
        :param bytes key_to_wrap: Key to wrap
        :returns: Wrapped key
        :rtype: bytes
        """
        if hasattr(self.cipher, 'wrap'):
            return self.cipher.wrap(wrapping_key, key_to_wrap)
        return self.cipher.encrypt(
            key=wrapping_key,
            data=key_to_wrap,
            mode=self.mode,
            padding=self.padding
        )

    def unwrap(self, wrapping_key, wrapped_key):
        """Wrap key using loaded key.

        :param wrapping_key: Key loaded by ``cipher``
        :param bytes wrapped_key: Wrapped key
        :returns: Unwrapped key
        :rtype: bytes
        """
        if hasattr(self.cipher, 'unwrap'):
            return self.cipher.unwrap(wrapping_key, wrapped_key)
        return self.cipher.decrypt(
            key=wrapping_key,
            data=wrapped_key,
            mode=self.mode,
            padding=self.padding
        )

    @property
    def transformation(self):
        """Returns the Java transformation describing this JavaCipher.
        https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher

        :returns: Formatted transformation
        :rtype: str
        """
        return '{cipher}/{mode}/{padding}'.format(
            cipher=self.cipher.java_name,
            mode=self.mode.java_name,
            padding=self.padding.java_name
        )

    @staticmethod
    def _map_load_or_error(name_type, name, mappings):
        """Load the requested name from mapping or raise an appropriate error.

        :param str name_type: Type of thing to load. This is used in the error message if name is not found in mappings.
        :param str name: Name to locate in mappings
        :param dict mappings: Dict in which to look for name
        """
        try:
            return mappings[name]
        except KeyError:
            raise JceTransformationError('Invalid {type} name: "{name}"'.format(
                type=name_type,
                name=name
            ))

    @classmethod
    def from_transformation(cls, cipher_transformation):
        """Generates an JavaCipher object from the Java transformation.
        https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher

        :param str cipher_transformation: Formatted transformation
        :returns: JavaCipher instance
        :rtype: JavaCipher
        """
        if cipher_transformation == 'AESWrap':
            # AESWrap does not support encrypt or decrypt, so mode and padding are never
            # used, but we use ECB and NoPadding as placeholders to simplify handling.
            return cls.from_transformation('AESWrap/ECB/NoPadding')

        if cipher_transformation == 'RSA':
            # RSA does not use mode, but as with JCE, we use ECB as a placeholder to simplify handling.
            return cls.from_transformation('RSA/ECB/PKCS1Padding')

        cipher_transformation_parts = cipher_transformation.split('/')
        if len(cipher_transformation_parts) != 3:
            raise JceTransformationError(
                'Invalid transformation: "{}": must be three parts ALGORITHM/MODE/PADDING, "RSA", or "AESWrap"'.format(
                    cipher_transformation
                )
            )

        cipher = cls._map_load_or_error('algorithm', cipher_transformation_parts[0], JAVA_ENCRYPTION_ALGORITHM)
        mode = cls._map_load_or_error('mode', cipher_transformation_parts[1], JAVA_MODE)
        padding = cls._map_load_or_error('padding', cipher_transformation_parts[2], JAVA_PADDING)

        return cls(cipher, mode, padding)
