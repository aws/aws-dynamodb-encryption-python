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
"""High-level helper class to provide a familiar interface to encrypted tables."""
from functools import partial

import attr
from boto3.resources.base import ServiceResource
from boto3.resources.collection import CollectionManager

from dynamodb_encryption_sdk.internal.utils import (
    crypto_config_from_cache, decrypt_batch_get_item, encrypt_batch_write_item, TableInfoCache
)
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions
from .item import decrypt_python_item, encrypt_python_item
from .table import EncryptedTable

__all__ = ('EncryptedResource',)


@attr.s
class EncryptedTablesCollectionManager(object):
    # pylint: disable=too-few-public-methods
    """Tables collection manager that provides EncryptedTable objects.

    https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.ServiceResource.tables

    :param collection: Pre-configured boto3 DynamoDB table collection manager
    :type collection: boto3.resources.collection.CollectionManager
    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param attribute_actions: Table-level configuration of how to encrypt/sign attributes
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    :param table_info_cache: Local cache from which to obtain TableInfo data
    :type table_info_cache: dynamodb_encryption_sdk.internal.utils.TableInfoCache
    """

    _collection = attr.ib(validator=attr.validators.instance_of(CollectionManager))
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    _attribute_actions = attr.ib(validator=attr.validators.instance_of(AttributeActions))
    _table_info_cache = attr.ib(validator=attr.validators.instance_of(TableInfoCache))

    def __attrs_post_init__(self):
        """Set up the translation methods."""
        self.all = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._transform_table,
            self._collection.all
        )
        self.filter = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._transform_table,
            self._collection.filter
        )
        self.limit = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._transform_table,
            self._collection.limit
        )
        self.page_size = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._transform_table,
            self._collection.page_size
        )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided collection object.

        :param str name: Attribute name
        :returns: Result of asking the provided collection object for that attribute name
        :raises AttributeError: if attribute is not found on provided collection object
        """
        return getattr(self._collection, name)

    def _transform_table(self, method, **kwargs):
        """Transform a Table from the underlying collection manager to an EncryptedTable.

        :param method: Method on underlying collection manager to call
        :type method: callable
        :param **kwargs: Keyword arguments to pass to ``method``
        """
        for table in method(**kwargs):
            yield EncryptedTable(
                table=table,
                materials_provider=self._materials_provider,
                table_info=self._table_info_cache.table_info(table.name),
                attribute_actions=self._attribute_actions
            )


@attr.s
class EncryptedResource(object):
    # pylint: disable=too-few-public-methods
    """High-level helper class to provide a familiar interface to encrypted tables.

    .. note::

        This class provides a superset of the boto3 DynamoDB service resource API, so should
        work as a drop-in replacement once configured.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#service-resource

        If you want to provide per-request cryptographic details, the ``batch_write_item``
        and ``batch_get_item`` methods will also accept a ``crypto_config`` parameter, defining
        a custom ``CryptoConfig`` instance for this request.

    :param resource: Pre-configured boto3 DynamoDB service resource object
    :type resource: boto3.resources.base.ServiceResource
    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param attribute_actions: Table-level configuration of how to encrypt/sign attributes
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table. (default: True)
    """

    _resource = attr.ib(validator=attr.validators.instance_of(ServiceResource))
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    _attribute_actions = attr.ib(
        validator=attr.validators.instance_of(AttributeActions),
        default=attr.Factory(AttributeActions)
    )
    _auto_refresh_table_indexes = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=True
    )

    def __attrs_post_init__(self):
        """Set up the table info cache, encrypted tables collection manager, and translation methods."""
        self._table_info_cache = TableInfoCache(  # attrs confuses pylint: disable=attribute-defined-outside-init
            client=self._resource.meta.client,
            auto_refresh_table_indexes=self._auto_refresh_table_indexes
        )
        self._crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_cache,
            materials_provider=self._materials_provider,
            attribute_actions=self._attribute_actions,
            table_info_cache=self._table_info_cache
        )
        self.tables = EncryptedTablesCollectionManager(  # attrs confuses pylint: disable=attribute-defined-outside-init
            collection=self._resource.tables,
            materials_provider=self._materials_provider,
            attribute_actions=self._attribute_actions,
            table_info_cache=self._table_info_cache
        )
        self.batch_get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_batch_get_item,
            decrypt_method=decrypt_python_item,
            crypto_config_method=self._crypto_config,
            read_method=self._resource.batch_get_item
        )
        self.batch_write_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_batch_write_item,
            encrypt_method=encrypt_python_item,
            crypto_config_method=self._crypto_config,
            write_method=self._resource.batch_write_item
        )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided resource object.

        :param str name: Attribute name
        :returns: Result of asking the provided resource object for that attribute name
        :raises AttributeError: if attribute is not found on provided resource object
        """
        return getattr(self._resource, name)

    def Table(self, name, **kwargs):
        # naming chosen to align with boto3 resource name, so pylint: disable=invalid-name
        """Creates an EncryptedTable resource.

        If any of the optional configuration values are not provided, the corresponding values
        for this ``EncryptedResource`` will be used.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.ServiceResource.Table

        :param name: The table name.
        :param materials_provider: Cryptographic materials provider to use (optional)
        :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
        :param table_info: Information about the target DynamoDB table (optional)
        :type table_info: dynamodb_encryption_sdk.structures.TableInfo
        :param attribute_actions: Table-level configuration of how to encrypt/sign attributes (optional)
        :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
        """
        table_kwargs = dict(
            table=self._resource.Table(name),
            materials_provider=kwargs.get('materials_provider', self._materials_provider),
            attribute_actions=kwargs.get('attribute_actions', self._attribute_actions),
            auto_refresh_table_indexes=kwargs.get('auto_refresh_table_indexes', self._auto_refresh_table_indexes),
            table_info=self._table_info_cache.table_info(name)
        )

        return EncryptedTable(**table_kwargs)
