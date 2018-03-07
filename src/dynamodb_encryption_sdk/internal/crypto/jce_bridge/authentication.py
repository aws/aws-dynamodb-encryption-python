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
"""Cryptographic authentication resources for JCE bridge."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import JavaBridge
from .primitives import load_rsa_key
from dynamodb_encryption_sdk.exceptions import InvalidAlgorithmError, SignatureVerificationError, SigningError

__all__ = ('JavaAuthenticator', 'JavaMac', 'JavaSignature')


class JavaAuthenticator(JavaBridge):
    """Parent class for all Java bridges that provide authentication characteristics."""
    __rlookup__ = {}


class JavaMac(JavaAuthenticator):
    """Symmetric MAC authenticators.

    https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac
    """

    # Symmetric Key Signatures
    # TODO: should we support these?
    # HmacMD5
    # HmacSHA1
    HMAC_SHA224 = ('HmacSHA224', hmac.HMAC, hashes.SHA224)
    HMAC_SHA256 = ('HmacSHA256', hmac.HMAC, hashes.SHA256)
    HMAC_SHA384 = ('HmacSHA384', hmac.HMAC, hashes.SHA384)
    HMAC_SHA512 = ('HmacSHA512', hmac.HMAC, hashes.SHA512)

    def __init__(self, algorithm_name, algorithm_type, hash_type):
        """Sets up a new JavaMac object.

        :param str algorithm_name: Java algorithm name
        :param algorithm_type: Native algorithm class
        :param hash_type: Native hashing class (if needed)
        """
        self.java_name = algorithm_name
        self.algorithm_type = algorithm_type
        self.hash_type = hash_type
        self.register()

    def _build_hmac_signer(self, key):
        """"""
        return self.algorithm_type(
            key,
            self.hash_type(),
            backend=default_backend()
        )

    def load_key(self, key, key_type, key_encoding):
        """"""
        return key

    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this signature.

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

        :param bytes key: Raw HMAC key
        :param bytes data: Data to sign
        :returns: Calculated signature
        :rtype: bytes
        """
        signer = self._build_hmac_signer(key)
        signer.update(data)
        return signer.finalize()

    def verify(self, key, signature, data):
        """

        :param bytes key: Raw HMAC key
        :param bytes signature: Signature to verify
        :param bytes data: Data over which to verify signature
        """
        verifier = self._build_hmac_signer(key)
        verifier.update(data)
        verifier.verify(signature)


class JavaSignature(JavaAuthenticator):
    """Asymmetric signature authenticators.

    https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
    """

    # Asymmetric Key Signatures
    # TODO: should we support these?
    # (NONE|SHA(1|224|256|384|512))with(|EC)DSA
    # (NONE|SHA1)withRSA
    SHA224_RSA = ('SHA224withRSA', rsa, hashes.SHA224, padding.PKCS1v15)
    SHA256_RSA = ('SHA256withRSA', rsa, hashes.SHA256, padding.PKCS1v15)
    SHA384_RSA = ('SHA384withRSA', rsa, hashes.SHA384, padding.PKCS1v15)
    SHA512_RSA = ('SHA512withRSA', rsa, hashes.SHA512, padding.PKCS1v15)

    def __init__(self, algorithm_name, algorithm_type, hash_type, padding_type):
        """Sets up a new JavaSignature object.

        :param str algorithm_name: Java algorithm name
        :param algorithm_type: Native algorithm class
        :param hash_type: Native hashing class (if needed)
        :param padding_type: Native padding class
        """
        self.java_name = algorithm_name
        self.algorithm_type = algorithm_type
        self.hash_type = hash_type
        self.padding_type = padding_type
        self.register()

    def validate_algorithm(self, algorithm):
        # type: (Text) -> None
        """Determine whether the requested algorithm name is compatible with this signature.

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
        """"""
        return load_rsa_key(key, key_type, key_encoding)

    def sign(self, key, data):
        """"""
        if hasattr(key, 'public_bytes'):
            raise SigningError('"sign" is not supported by public keys')
        # TODO: normalize to SigningError
        return key.sign(
            data,
            self.padding_type(),
            self.hash_type()
        )

    def verify(self, key, signature, data):
        """"""
        if hasattr(key, 'private_bytes'):
            _key = key.public_key()
        else:
            _key = key
        # TODO: normalize to SignatureVerificationError
        _key.verify(
            signature,
            data,
            self.padding_type(),
            self.hash_type()
        )
