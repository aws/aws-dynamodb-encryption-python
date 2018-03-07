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
import attr

from . import CryptoConfig
from .item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext, TableInfo

__all__ = ('EncryptedTable',)


@attr.s(hash=False)
class EncryptedTable(object):
    """High-level helper class to provide a familiar interface to encrypted tables.

    .. note::

        This class provides a superset of the boto3 DynamoDB Table API, so should work as
        a drop-in replacement once configured.

        If you want to provide per-request cryptographic details, the ``put_item``, ``get_item``,
        ``query``, and ``scan`` methods will also accept any of the following parameters:

        * ``CryptoConfig`` : Defines a custom ``CryptoConfig`` instance for this request.
          If provided, all below parameters are ignored.
        * ``MaterialsProvider`` : Defines a custom cryptographic materials provider for this
          request. If not provided, the table-level materials provider is used.
        * ``AttributeActions`` : Defines a custom ``AttributeActions`` instance for this
          request. If not provided, the table-level attribute actions is used.
        * ``EncryptionContext`` : Defines a custom ``EncryptionContext`` instance for this
          request. If not provided, one is generated based on the table-level configuration.
        * ``MaterialDescription`` : Defines a custom material description for this request.

    .. warning::

        We do not currently support the ``update_item`` method.

    :param table: Pre-configured boto3 DynamoDB Table object
    :type table: TODO:
    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param table_info: Information about the target DynamoDB table
    :type table_info: dynamodb_encryption_sdk.structures.TableInfo
    :param attribute_actions: Table-level configuration of how to encrypt/sign attributes
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    """
    _table = attr.ib()
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    _table_info = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(TableInfo)),
        default=None
    )
    _attribute_actions = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AttributeActions)),
        default=attr.Factory(AttributeActions)
    )

    def __attrs_post_init__(self):
        """Prepare table info is it was not set."""
        if self._table_info is None:
            self._table_info = TableInfo(name=self._table.name)

        self._attribute_actions.set_index_keys(*self._table_info.all_index_keys())

        self._encryption_context_table_data = {'table_name': self._table_info.name}
        if self._table_info.primary_index is not None:
            self._encryption_context_table_data.update(dict(
                partition_key_name=self._table_info.primary_index.partition,
                sort_key_name=self._table_info.primary_index.sort
            ))

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided table object.

        :param str name: Attribute name
        :returns: Result of asking the provided table object for that attribute name
        :raises AttributeError: if attribute is not found on provided table object
        """
        return getattr(self._table, name)

    def _extract_crypto_config(self, **kwargs):
        """Pull all encryption-specific parameters from the request and use them to build a crypto config.

        :returns: crypto config and updated kwargs
        :rtype: dynamodb_encryption_sdk.encrypted.CryptoConfig and dict
        """
        crypto_config = kwargs.pop('CryptoConfig', None)
        materials_provider = kwargs.pop('MaterialsProvider', self._materials_provider)
        material_description = kwargs.pop('MaterialDescription', {})
        encryption_context = kwargs.pop('EncryptionContext', None)
        attribute_actions = kwargs.pop('AttributeActions', self._attribute_actions)

        if crypto_config is not None:
            return crypto_config, kwargs

        if encryption_context is None:
            encryption_context = EncryptionContext(
                material_description=material_description,
                **self._encryption_context_table_data
            )

        crypto_config = CryptoConfig(
            materials_provider=materials_provider,
            encryption_context=encryption_context,
            attribute_actions=attribute_actions
        )
        return crypto_config, kwargs

    def put_item(self, **kwargs):
        """Transparently encrypt an item before putting it to the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Table.get_item
        """
        crypto_config, ddb_kwargs = self._extract_crypto_config(**kwargs)

        ddb_kwargs['Item'] = encrypt_python_item(
            item=ddb_kwargs['Item'],
            crypto_config=crypto_config
        )
        return self._table.put_item(**ddb_kwargs)

    def get_item(self, **kwargs):
        """Transparently decrypt an item after getting it from the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Table.get_item
        """
        crypto_config, ddb_kwargs = self._extract_crypto_config(**kwargs)

        # TODO: update projection expression
        # TODO: check for unsupported parameters
        response = self._table.get_item(**ddb_kwargs)
        if 'Item' in response:
            response['Item'] = decrypt_python_item(
                item=response['Item'],
                crypto_config=crypto_config
            )
        return response

    def update_item(self, **kwargs):
        """Update item is not yet supported.
        """
        raise NotImplementedError('"update_item" is not yet implemented')

    def _multi_result(self, method, **kwargs):
        """Transparently decrypt multiple items after getting them from the table.

        :param method: Method from underlying DynamoDB table object to use
        :type method: callable
        """
        crypto_config, ddb_kwargs = self._extract_crypto_config(**kwargs)

        # TODO: update projection expression
        # TODO: check for unsupported parameters
        response = method(**ddb_kwargs)
        for item in response['Items']:
            item = decrypt_python_item(
                item=item,
                crypto_config=crypto_config
            )
        return response

    def query(self, **kwargs):
        """Transparently decrypt multiple items after getting them from the table with a query.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Table.query
        """
        self._multi_result(method=self._table.query, **kwargs)

    def scan(self, **kwargs):
        """Transparently decrypt multiple items after getting them from the table with a scan.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Table.scan
        """
        self._multi_result(method=self._table.scan, **kwargs)
