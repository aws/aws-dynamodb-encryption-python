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
"""Meta cryptographic provider store."""
from enum import Enum

import attr
from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import Binary
from boto3.resources.base import ServiceResource
import botocore

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Optional, Text, Tuple  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk.exceptions import InvalidVersionError, NoKnownVersionError, VersionAlreadyExistsError
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from . import ProviderStore

__all__ = ('MetaStore',)


class MetaStoreAttributeNames(Enum):
    """Names of attributes in the MetaStore table."""

    PARTITION = 'N'
    SORT = 'V'
    INTEGRITY_ALGORITHM = 'intAlg'
    INTEGRITY_KEY = 'int'
    ENCRYPTION_ALGORITHM = 'encAlg'
    ENCRYPTION_KEY = 'enc'
    MATERIAL_TYPE_VERSION = 't'


class MetaStoreValues(Enum):
    """Static values for use by MetaStore."""

    INTEGRITY_ALGORITHM = 'HmacSHA256'
    ENCRYPTION_ALGORITHM = 'AES'
    MATERIAL_TYPE_VERSION = '0'
    KEY_BITS = 256


#: Field in material description to use for the MetaStore material name and version.
_MATERIAL_DESCRIPTION_META_FIELD = 'amzn-ddb-meta-id'


@attr.s(init=False)
class MetaStore(ProviderStore):
    """Create and retrieve wrapped cryptographic materials providers, storing their cryptographic
    materials using the provided encrypted table.

    :param table: Pre-configured boto3 DynamoDB Table object
    :type table: boto3.resources.base.ServiceResource
    :param CryptographicMaterialsProvider materials_provider: Cryptographic materials provider to use
    """

    _table = attr.ib(validator=attr.validators.instance_of(ServiceResource))
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))

    def __init__(self, table, materials_provider):  # noqa=D107
        # type: (ServiceResource, CryptographicMaterialsProvider) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._table = table
        self._materials_provider = materials_provider
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepare the encrypted table resource from the provided table and materials provider."""
        self._encrypted_table = EncryptedTable(  # attrs confuses pylint: disable=attribute-defined-outside-init
            table=self._table,
            materials_provider=self._materials_provider
        )

    @classmethod
    def create_table(cls, client, table_name, read_units, write_units):
        # type: (botocore.client.BaseClient, Text, int, int) -> None
        """Create the table for this MetaStore.

        :param table: Pre-configured boto3 DynamoDB client object
        :type table: boto3.resources.base.BaseClient
        :param str table_name: Name of table to create
        :param int read_units: Read capacity units to provision
        :param int write_units: Write capacity units to provision
        """
        try:
            client.create_table(
                TableName=table_name,
                AttributeDefinitions=[
                    {
                        'AttributeName': MetaStoreAttributeNames.PARTITION.value,
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': MetaStoreAttributeNames.SORT.value,
                        'AttributeType': 'N'
                    }
                ],
                KeySchema=[
                    {
                        'AttributeName': MetaStoreAttributeNames.PARTITION.value,
                        'KeyType': 'HASH'
                    },
                    {
                        'AttributeName': MetaStoreAttributeNames.SORT.value,
                        'KeyType': 'RANGE'
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': read_units,
                    'WriteCapacityUnits': write_units
                }
            )
        except botocore.exceptions.ClientError:
            raise Exception('TODO: Could not create table')

    def _load_materials(self, material_name, version):
        # type: (Text, int) -> Tuple[JceNameLocalDelegatedKey, JceNameLocalDelegatedKey]
        """Load materials from table.

        :returns: Materials loaded into delegated keys
        :rtype: tuple(JceNameLocalDelegatedKey)
        """
        key = {
            MetaStoreAttributeNames.PARTITION.value: material_name,
            MetaStoreAttributeNames.SORT.value: version
        }
        response = self._encrypted_table.get_item(Key=key)
        try:
            item = response['Item']
        except KeyError:
            raise InvalidVersionError('Version not found: "{}#{}"'.format(material_name, version))

        try:
            encryption_key_kwargs = dict(
                key=item[MetaStoreAttributeNames.ENCRYPTION_KEY.value].value,
                algorithm=item[MetaStoreAttributeNames.ENCRYPTION_ALGORITHM.value],
                key_type=EncryptionKeyType.SYMMETRIC,
                key_encoding=KeyEncodingType.RAW
            )
            signing_key_kwargs = dict(
                key=item[MetaStoreAttributeNames.INTEGRITY_KEY.value].value,
                algorithm=item[MetaStoreAttributeNames.INTEGRITY_ALGORITHM.value],
                key_type=EncryptionKeyType.SYMMETRIC,
                key_encoding=KeyEncodingType.RAW
            )
        except KeyError:
            raise Exception('TODO: Invalid record')

        # TODO: handle if the material type version is not in the item
        if item[MetaStoreAttributeNames.MATERIAL_TYPE_VERSION.value] != MetaStoreValues.MATERIAL_TYPE_VERSION.value:
            raise InvalidVersionError('Unsupported material type: "{}"'.format(
                item[MetaStoreAttributeNames.MATERIAL_TYPE_VERSION.value]
            ))

        encryption_key = JceNameLocalDelegatedKey(**encryption_key_kwargs)
        signing_key = JceNameLocalDelegatedKey(**signing_key_kwargs)
        return encryption_key, signing_key

    def _save_materials(self, material_name, version, encryption_key, signing_key):
        # type: (Text, int, JceNameLocalDelegatedKey, JceNameLocalDelegatedKey) -> None
        """Save materials to the table, raising an error if the version already exists.

        :param str material_name: Material to locate
        :param int version: Version of material to locate
        :raises VersionAlreadyExistsError: if the specified version already exists
        """
        item = {
            MetaStoreAttributeNames.PARTITION.value: material_name,
            MetaStoreAttributeNames.SORT.value: version,
            MetaStoreAttributeNames.MATERIAL_TYPE_VERSION.value: MetaStoreValues.MATERIAL_TYPE_VERSION.value,
            MetaStoreAttributeNames.ENCRYPTION_ALGORITHM.value: encryption_key.algorithm,
            MetaStoreAttributeNames.ENCRYPTION_KEY.value: Binary(encryption_key.key),
            MetaStoreAttributeNames.INTEGRITY_ALGORITHM.value: signing_key.algorithm,
            MetaStoreAttributeNames.INTEGRITY_KEY.value: Binary(signing_key.key)
        }
        try:
            self._encrypted_table.put_item(
                Item=item,
                ConditionExpression=(
                    Attr(MetaStoreAttributeNames.PARTITION.value).not_exists() &
                    Attr(MetaStoreAttributeNames.SORT.value).not_exists()
                )
            )
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'ConditionalCheckFailedException':
                raise VersionAlreadyExistsError('Version already exists: "{}#{}"'.format(material_name, version))

    def _save_or_load_materials(
            self,
            material_name,  # type: Text
            version,  # type: int
            encryption_key,  # type: JceNameLocalDelegatedKey
            signing_key  # type: JceNameLocalDelegatedKey
    ):
        # type: (...) -> Tuple[JceNameLocalDelegatedKey, JceNameLocalDelegatedKey]
        """Attempt to save the materials to the table.

        If the specified version already exists, the existing materials will be loaded from
        the table and returned. Otherwise, the provided materials will be returned.

        :param str material_name: Material to locate
        :param int version: Version of material to locate
        :param JceNameLocalDelegatedKey encryption_key: Loaded encryption key
        :param JceNameLocalDelegatedKey signing_key: Loaded signing key
        """
        try:
            self._save_materials(material_name, version, encryption_key, signing_key)
            return encryption_key, signing_key
        except VersionAlreadyExistsError:
            return self._load_materials(material_name, version)

    @staticmethod
    def _material_description(material_name, version):
        # type: (Text, int) -> Dict[Text, Text]
        """Build a material description from a material name and version.

        :param str material_name: Material to locate
        :param int version: Version of material to locate
        """
        return {_MATERIAL_DESCRIPTION_META_FIELD: '{name}#{version}'.format(name=material_name, version=version)}

    def _load_provider_from_table(self, material_name, version):
        # type: (Text, int) -> CryptographicMaterialsProvider
        """Load a provider from the table.

        If the requested version does not exist, an error will be raised.

        :param str material_name: Material to locate
        :param int version: Version of material to locate
        """
        encryption_key, signing_key = self._load_materials(material_name, version)
        return WrappedCryptographicMaterialsProvider(
            signing_key=signing_key,
            wrapping_key=encryption_key,
            unwrapping_key=encryption_key,
            material_description=self._material_description(material_name, version)
        )

    def get_or_create_provider(self, material_name, version):
        # type: (Text, int) -> CryptographicMaterialsProvider
        """Obtain a cryptographic materials provider identified by a name and version.

        If the requested version does not exist, a new one will be created.

        :param str material_name: Material to locate
        :param int version: Version of material to locate
        :returns: cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        :raises InvalidVersionError: if the requested version is not available and cannot be created
        """
        encryption_key = JceNameLocalDelegatedKey.generate(
            MetaStoreValues.ENCRYPTION_ALGORITHM.value,
            MetaStoreValues.KEY_BITS.value
        )
        signing_key = JceNameLocalDelegatedKey.generate(
            MetaStoreValues.INTEGRITY_ALGORITHM.value,
            MetaStoreValues.KEY_BITS.value
        )
        encryption_key, signing_key = self._save_or_load_materials(material_name, version, encryption_key, signing_key)
        return WrappedCryptographicMaterialsProvider(
            signing_key=signing_key,
            wrapping_key=encryption_key,
            unwrapping_key=encryption_key,
            material_description=self._material_description(material_name, version)
        )

    def provider(self, material_name, version=None):
        # type: (Text, Optional[int]) -> CryptographicMaterialsProvider
        """Obtain a cryptographic materials provider identified by a name and version.

        If the version is provided, an error will be raised if that version is not found.

        If the version is not provided, the maximum version will be used.

        :param str material_name: Material to locate
        :param int version: Version of material to locate (optional)
        :returns: cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        :raises InvalidVersionError: if the requested version is not found
        """
        if version is not None:
            return self._load_provider_from_table(material_name, version)

        return super(MetaStore, self).provider(material_name, version)

    def version_from_material_description(self, material_description):
        # (Dict[Text, Text]) -> int
        """Determine the version from the provided material description.

        :param dict material_description: Material description to use with this request
        :returns: version to use
        :rtype: int
        """
        try:
            info = material_description[_MATERIAL_DESCRIPTION_META_FIELD]
        except KeyError:
            raise Exception('TODO: No info found')

        try:
            return int(info.split('#', 1)[1])
        except (IndexError, ValueError):
            raise Exception('TODO: Malformed info')

    def max_version(self, material_name):
        # (Text) -> int
        """Find the maximum known version of the specified material.

        :param str material_name: Material to locate
        :returns: Maximum known version
        :rtype: int
        :raises NoKnownVersion: if no version can be found
        """
        response = self._encrypted_table.query(
            KeyConditionExpression=Key(MetaStoreAttributeNames.PARTITION.value).eq(material_name),
            ScanIndexForward=False,
            Limit=1
        )

        if not response['Items']:
            raise NoKnownVersionError('No known version for name: "{}"'.format(material_name))

        return int(response['Items'][0][MetaStoreAttributeNames.SORT.value])
