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
"""Cipher resource for JCE bridge."""
import attr

from .primitives import JavaEncryptionAlgorithm, JavaMode, JavaPadding

__all__ = ('JavaCipher',)


@attr.s(hash=False)
class JavaCipher(object):
    """Defines the encryption cipher, mode, and padding type to use for encryption.

    https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

    :param cipher: TODO:
    :param mode: TODO:
    :param padding: TODO:
    """
    cipher = attr.ib(validator=attr.validators.instance_of(JavaEncryptionAlgorithm))
    mode = attr.ib(validator=attr.validators.instance_of(JavaMode))
    padding = attr.ib(validator=attr.validators.instance_of(JavaPadding))

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

    @classmethod
    def from_transformation(cls, cipher_transformation):
        """Generates an JavaCipher object from the Java transformation.
        https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher

        :param str cipher_transformation: Formatted transformation
        :returns: JavaCipher instance
        :rtype: dynamodb_encryption_sdk.internal.structures.EncryptionClient
        """
        # TODO: I'm pretty sure these are sane defaults, but verify with someone more familiar with JCE.
        if cipher_transformation == 'AESWrap':
            return cls.from_transformation('AES/GCM/NoPadding')

        if cipher_transformation == 'RSA':
            return cls.from_transformation('RSA/ECB/PKCS1Padding')

        cipher_transformation = cipher_transformation.split('/')
        return cls(
            cipher=JavaEncryptionAlgorithm.from_name(cipher_transformation[0]),
            mode=JavaMode.from_name(cipher_transformation[1]),
            padding=JavaPadding.from_name(cipher_transformation[2])
        )
