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
"""Cryptographic materials provider for use with the AWS Key Management Service (KMS)."""
from __future__ import division
import base64
from enum import Enum

import attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import boto3
import botocore.client
import botocore.session
import six

from . import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.exceptions import UnknownRegionError, UnwrappingError, WrappingError
from dynamodb_encryption_sdk.identifiers import EncryptionKeyTypes, KeyEncodingType
from dynamodb_encryption_sdk.internal import dynamodb_types
from dynamodb_encryption_sdk.internal.identifiers import MaterialDescriptionKeys
from dynamodb_encryption_sdk.internal.str_ops import to_bytes, to_str
from dynamodb_encryption_sdk.internal.validators import dictionary_validator, iterable_validator
from dynamodb_encryption_sdk.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext

__all__ = ('AwsKmsCryptographicMaterialsProvider',)

_COVERED_ATTR_CTX_KEY = 'aws-kms-ec-attr'
_TABLE_NAME_EC_KEY = '*aws-kms-table*'
_DEFAULT_CONTENT_ENCRYPTION_ALGORITHM = 'AES/256'
_DEFAULT_CONTENT_KEY_LENGTH = 256
_DEFAULT_SIGNING_ALGORITHM = 'HmacSHA256/256'
_DEFAULT_SIGNING_KEY_LENGTH = 256
_KEY_COVERAGE = '*keys*'
_KDF_ALG = 'HmacSHA256'


class HkdfInfo(Enum):
    """Info strings used for HKDF calculations."""
    ENCRYPTION = b'Encryption'
    SIGNING = b'Signing'


class EncryptionContextKeys(Enum):
    """Special keys for use in the AWS KMS encryption context."""
    CONTENT_ENCRYPTION_ALGORITHM = '*' + MaterialDescriptionKeys.CONTENT_ENCRYPTION_ALGORITHM.value + '*'
    SIGNATURE_ALGORITHM = '*' + MaterialDescriptionKeys.ITEM_SIGNATURE_ALGORITHM.value + '*'
    TABLE_NAME = '*aws-kms-table*'


@attr.s
class KeyInfo(object):
    """Identifying information for a specific key and how it should be used.

    :param str description: algorithm identifier joined with key length in bits
    :param str algorithm: algorithm identifier
    :param int length: Key length in bits
    """
    description = attr.ib(validator=attr.validators.instance_of(six.string_types))
    algorithm = attr.ib(validator=attr.validators.instance_of(six.string_types))
    length = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    @classmethod
    def from_material_description(cls, material_description, description_key, default_algorithm, default_key_length):
        # type: (Dict[Text, Text], Text, Text, int) -> KeyInfo
        """Load key info from material description.

        :param dict material_description: Material description to read
        :param str description_key: Material description key containing desired key info description
        :param str default_algorithm: Algorithm name to use if not found in material description
        :param int default_key_length: Key length to use if not found in material description
        :returns: Key info loaded from material description, with defaults applied if necessary
        :rtype: dynamodb_encryption_sdk.material_providers.aws_kms.KeyInfo
        """
        description = material_description.get(description_key, default_algorithm)
        description_parts = description.split('/', 1)
        algorithm = description_parts[0]
        try:
            key_length = int(description_parts[1])
        except IndexError:
            key_length = default_key_length
        return cls(description, algorithm, key_length)


@attr.s
class AwsKmsCryptographicMaterialsProvider(CryptographicMaterialsProvider):
    """Cryptographic materials provider for use with the AWS Key Management Service (KMS).

    .. note::

        This cryptographic materials provider makes one AWS KMS API call each time encryption
        or decryption materials are requested. This means that one request will be made for
        each item that you read or write.

    :param str key_id: ID of AWS KMS CMK to use
    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations (optional)
    :param dict material_description: Material description to use as default state for this CMP (optional)
    :param dict regional_clients: Dictionary mapping AWS region names to pre-configured boto3
        KMS clients (optional)
    """
    _key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _botocore_session = attr.ib(
        validator=attr.validators.instance_of(botocore.session.Session),
        default=attr.Factory(botocore.session.Session)
    )
    _grant_tokens = attr.ib(
        validator=iterable_validator(tuple, six.string_types),
        default=attr.Factory(tuple)
    )
    _material_description = attr.ib(
        validator=dictionary_validator(six.string_types, six.string_types),
        default=attr.Factory(dict)
    )
    _regional_clients = attr.ib(
        validator=dictionary_validator(six.string_types, botocore.client.BaseClient),
        default=attr.Factory(dict)
    )

    def __attrs_post_init__(self):
        # type: () -> None
        """Load the content and signing key info."""
        self._content_key_info = KeyInfo.from_material_description(
            material_description=self._material_description,
            description_key=MaterialDescriptionKeys.CONTENT_ENCRYPTION_ALGORITHM.value,
            default_algorithm=_DEFAULT_CONTENT_ENCRYPTION_ALGORITHM,
            default_key_length=_DEFAULT_CONTENT_KEY_LENGTH
        )
        self._signing_key_info = KeyInfo.from_material_description(
            material_description=self._material_description,
            description_key=MaterialDescriptionKeys.ITEM_SIGNATURE_ALGORITHM.value,
            default_algorithm=_DEFAULT_SIGNING_ALGORITHM,
            default_key_length=_DEFAULT_SIGNING_KEY_LENGTH
        )
        self._regional_clients = {}

    def _add_regional_client(self, region_name):
        # type: (Text) -> None
        """Adds a regional client for the specified region if it does not already exist.

        :param str region_name: AWS Region ID (ex: us-east-1)
        """
        if region_name not in self._regional_clients:
            self._regional_clients[region_name] = boto3.session.Session(
                region_name=region_name,
                botocore_session=self._botocore_session
            ).client('kms')

    def _client(self, key_id):
        """Returns a boto3 KMS client for the appropriate region.

        :param str key_id: KMS CMK ID
        :returns: Boto3 KMS client for requested key id
        :rtype: botocore.client.KMS
        """
        region = self._botocore_session.get_config_variable('region')
        if region is None:
            try:
                region_name = key_id.split(':', 4)[3]
                region = region_name
            except IndexError:
                if region is None:
                    raise UnknownRegionError(
                        'No default region found and no region determinable from key id: {}'.format(key_id)
                    )
        self._add_regional_client(region)
        return self._regional_clients[region]

    def _select_key_id(self, encryption_context):
        # type: (EncryptionContext) -> Text
        """Select the desired key id.

        .. note::

            Default behavior is to use the key id provided on creation, but this method provides
            an extension point for a CMP that might select a different key id based on the
            encryption context.

        :param encryption_context: Encryption context providing information about request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Key id to use
        :rtype: str
        """
        return self._key_id

    def _validate_key_id(self, key_id, encryption_context):
        """Validate the selected key id.

        .. note::

            Default behavior is to do nothing, but this method provides an extension point
            for a CMP that overrides ``_select_key_id`` or otherwise wants to validate a
            key id before it is used.

        :param encryption_context: Encryption context providing information about request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        """

    def _attribute_to_value(self, attribute):
        # type: (dynamodb_types.ITEM) -> str
        """Convert a DynamoDB attribute to a value that can be added to the KMS encryption context.

        :param dict attribute: Attribute to convert
        :returns: value from attribute, ready to be addd to the KMS encryption context
        :rtype: str
        """
        attribute_type, attribute_value = list(attribute.items())[0]
        if attribute_type == 'B':
            return base64.b64encode(attribute_value.value).decode('utf-8')
        if attribute_type == 'S':
            return attribute_value
        raise ValueError('Attribute of type "{}" cannot be used in KMS encryption context.'.format(attribute_type))

    def _kms_encryption_context(self, encryption_context, encryption_description, signing_description):
        # type: (EncryptionContext, Text, Text) -> Dict[str, str]
        """Build the KMS encryption context from the encryption context and key descriptions.

        :param encryption_context: Encryption context providing information about request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :param str encryption_description: Description value from encryption KeyInfo
        :param str signing_description: Description value from signing KeyInfo
        :returns: KMS encryption context for use in request
        :rtype: dict
        """
        kms_encryption_context = {
            EncryptionContextKeys.CONTENT_ENCRYPTION_ALGORITHM.value: encryption_description,
            EncryptionContextKeys.SIGNATURE_ALGORITHM.value: signing_description
        }

        if encryption_context.partition_key_name is not None:
            partition_key_attribute = encryption_context.attributes.get(encryption_context.partition_key_name)
            kms_encryption_context[encryption_context.partition_key_name] = self._attribute_to_value(
                partition_key_attribute
            )

        if encryption_context.sort_key_name is not None:
            sort_key_attribute = encryption_context.attributes.get(encryption_context.sort_key_name)
            kms_encryption_context[encryption_context.sort_key_name] = self._attribute_to_value(sort_key_attribute)

        if encryption_context.table_name is not None:
            kms_encryption_context[_TABLE_NAME_EC_KEY] = encryption_context.table_name

        return kms_encryption_context

    def _generate_initial_material(self, encryption_context):
        # type: () -> (bytes, bytes)
        """Generate the initial cryptographic material for use with HKDF.

        :param encryption_context: Encryption context providing information about request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Plaintext and ciphertext of initial cryptographic material
        :rtype: bytes and bytes
        """
        key_id = self._select_key_id(encryption_context)
        self._validate_key_id(key_id, encryption_context)
        key_length = 256 // 8
        kms_encryption_context = self._kms_encryption_context(
            encryption_context=encryption_context,
            encryption_description=self._content_key_info.description,
            signing_description=self._signing_key_info.description
        )
        kms_params = dict(
            KeyId=key_id,
            NumberOfBytes=key_length,
            EncryptionContext=kms_encryption_context
        )
        if self._grant_tokens:
            kms_params['GrantTokens'] = self._grant_tokens
        # Catch any boto3 errors and normalize to expected WrappingError
        try:
            response = self._client(key_id).generate_data_key(**kms_params)
            return response['Plaintext'], response['CiphertextBlob']
        except (botocore.exceptions.ClientError, KeyError):
            raise WrappingError('TODO:SOMETHING')

    def _decrypt_initial_material(self, encryption_context):
        # type: () -> bytes
        """Decrypt an encrypted initial cryptographic material value.

        :param encryption_context: Encryption context providing information about request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Plaintext of initial cryptographic material
        :rtype: bytes
        """
        key_id = self._select_key_id(encryption_context)
        self._validate_key_id(key_id, encryption_context)
        kms_encryption_context = self._kms_encryption_context(
            encryption_context=encryption_context,
            encryption_description=encryption_context.material_description.get(
                MaterialDescriptionKeys.CONTENT_ENCRYPTION_ALGORITHM.value
            ),
            signing_description=encryption_context.material_description.get(
                MaterialDescriptionKeys.ITEM_SIGNATURE_ALGORITHM.value
            )
        )
        encrypted_initial_material = base64.b64decode(to_bytes(encryption_context.material_description.get(
            MaterialDescriptionKeys.WRAPPED_DATA_KEY.value
        )))
        kms_params = dict(
            CiphertextBlob=encrypted_initial_material,
            EncryptionContext=kms_encryption_context
        )
        if self._grant_tokens:
            kms_params['GrantTokens'] = self._grant_tokens
        # Catch any boto3 errors and normalize to expected UnwrappingError
        try:
            response = self._client(key_id).decrypt(**kms_params)
            return response['Plaintext']
        except (botocore.exceptions.ClientError, KeyError):
            raise UnwrappingError('TODO:SOMETHING')

    def _hkdf(self, initial_material, key_length, info):
        # type: (bytes, int, Text) -> bytes
        """Use HKDF to derive a key.

        :param bytes initial_material: Initial material to use with HKDF
        :param int key_length: Length of key to derive
        :param str info: Info value to use in HKDF calculate
        :returns: Derived key material
        :rtype: bytes
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(initial_material)

    def _derive_delegated_key(self, initial_material, key_info, hkdf_info):
        # type: (bytes, KeyInfo, HkdfInfo) -> JceNameLocalDelegatedKey
        """Derive the raw key and use it to build a JceNameLocalDelegatedKey.

        :param bytes initial_material: Initial material to use with KDF
        :param key_info: Key information to use to calculate encryption key
        :type key_info: dynamodb_encryption_sdk.material_providers.aws_kms.KeyInfo
        :param hkdf_info: Info to use in HKDF calculation
        :type hkdf_info: dynamodb_encryption_sdk.material_providers.aws_kms.HkdfInfo
        :returns: Delegated key to use for encryption and decryption
        :rtype: dynamodb_encryption_sdk.delegated_keys.jce.JceNameLocalDelegatedKey
        """
        raw_key = self._hkdf(initial_material, key_info.length // 8, hkdf_info.value)
        return JceNameLocalDelegatedKey(
            key=raw_key,
            algorithm=key_info.algorithm,
            key_type=EncryptionKeyTypes.SYMMETRIC,
            key_encoding=KeyEncodingType.RAW
        )

    def _encryption_key(self, initial_material, key_info):
        # type: (bytes, KeyInfo) -> JceNameLocalDelegatedKey
        """Calculate an encryption key from ``initial_material`` using the requested key info.

        :param bytes initial_material: Initial material to use with KDF
        :param key_info: Key information to use to calculate encryption key
        :type key_info: dynamodb_encryption_sdk.material_providers.aws_kms.KeyInfo
        :returns: Delegated key to use for encryption and decryption
        :rtype: dynamodb_encryption_sdk.delegated_keys.jce.JceNameLocalDelegatedKey
        """
        return self._derive_delegated_key(initial_material, key_info, HkdfInfo.ENCRYPTION)

    def _mac_key(self, initial_material, key_info):
        # type: (bytes, KeyInfo) -> JceNameLocalDelegatedKey
        """Calculate an HMAC key from ``initial_material`` using the requested key info.

        :param bytes initial_material: Initial material to use with KDF
        :param key_info: Key information to use to calculate HMAC key
        :type key_info: dynamodb_encryption_sdk.material_providers.aws_kms.KeyInfo
        :returns: Delegated key to use for signature calculation and verification
        :rtype: dynamodb_encryption_sdk.delegated_keys.jce.JceNameLocalDelegatedKey
        """
        return self._derive_delegated_key(initial_material, key_info, HkdfInfo.SIGNING)

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> RawDecryptionMaterials
        """Provide decryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Encryption materials
        :rtype: dynamodb_encryption_sdk.materials.wrapped.RawDecryptionMaterials
        """
        decryption_material_description = encryption_context.material_description.copy()
        initial_material = self._decrypt_initial_material(encryption_context)
        signing_key_info = KeyInfo.from_material_description(
            material_description=encryption_context.material_description,
            description_key=MaterialDescriptionKeys.ITEM_SIGNATURE_ALGORITHM.value,
            default_algorithm=_DEFAULT_SIGNING_ALGORITHM,
            default_key_length=_DEFAULT_SIGNING_KEY_LENGTH
        )
        decryption_key_info = KeyInfo.from_material_description(
            material_description=encryption_context.material_description,
            description_key=MaterialDescriptionKeys.CONTENT_ENCRYPTION_ALGORITHM.value,
            default_algorithm=_DEFAULT_CONTENT_ENCRYPTION_ALGORITHM,
            default_key_length=_DEFAULT_CONTENT_KEY_LENGTH
        )
        return RawDecryptionMaterials(
            verification_key=self._mac_key(initial_material, signing_key_info),
            decryption_key=self._encryption_key(initial_material, decryption_key_info),
            material_description=decryption_material_description
        )

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> RawEncryptionMaterials
        """Provide encryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :returns: Encryption materials
        :rtype: dynamodb_encryption_sdk.materials.wrapped.RawEncryptionMaterials
        """
        initial_material, encrypted_initial_material = self._generate_initial_material(encryption_context)
        encryption_material_description = encryption_context.material_description.copy()
        encryption_material_description.update({
            _COVERED_ATTR_CTX_KEY: _KEY_COVERAGE,
            MaterialDescriptionKeys.CONTENT_KEY_WRAPPING_ALGORITHM.value: 'kms',
            MaterialDescriptionKeys.CONTENT_ENCRYPTION_ALGORITHM.value: self._content_key_info.description,
            MaterialDescriptionKeys.ITEM_SIGNATURE_ALGORITHM.value: self._signing_key_info.description,
            MaterialDescriptionKeys.WRAPPED_DATA_KEY.value: to_str(base64.b64encode(encrypted_initial_material))
        })
        return RawEncryptionMaterials(
            signing_key=self._mac_key(initial_material, self._signing_key_info),
            encryption_key=self._encryption_key(initial_material, self._content_key_info),
            material_description=encryption_material_description
        )
