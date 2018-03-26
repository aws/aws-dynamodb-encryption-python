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
""""""
import attr
import botocore.client

from . import CryptoConfig, validate_get_arguments
from .item import decrypt_dynamodb_item, encrypt_dynamodb_item
from dynamodb_encryption_sdk.internal.utils import TableInfoCache
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext

__all__ = ('EncryptedClient',)


@attr.s
class EncryptedClient(object):
    """High-level helper class to provide a familiar interface to encrypted tables.

    .. note::

        This class provides a superset of the boto3 DynamoDB client API, so should work as
        a drop-in replacement once configured.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#client

    .. warning::

        We do not currently support the ``update_item`` method.

    """
    _client = attr.ib(validator=attr.validators.instance_of(botocore.client.BaseClient))
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
        """Set up the table info cache."""
        self._table_info_cache = TableInfoCache(
            client=self._client,
            auto_refresh_table_indexes=self._auto_refresh_table_indexes
        )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided client object.

        :param str name: Attribute name
        :returns: Result of asking the provided client object for that attribute name
        :raises AttributeError: if attribute is not found on provided client object
        """
        return getattr(self._client, name)

    def _crypto_config(self, table_name, **kwargs):
        """Pull all encryption-specific parameters from the request and use them to build a crypto config.

        :returns: crypto config and updated kwargs
        :rtype: dynamodb_encryption_sdk.encrypted.CryptoConfig and dict
        """
        crypto_config = kwargs.pop('crypto_config', None)

        if crypto_config is not None:
            return crypto_config, kwargs

        table_info = self._table_info_cache.table_info(table_name)

        attribute_actions = self._attribute_actions.copy()
        attribute_actions.set_index_keys(*table_info.protected_index_keys())

        crypto_config = CryptoConfig(
            materials_provider=self._materials_provider,
            encryption_context=EncryptionContext(**table_info.encryption_context_values),
            attribute_actions=attribute_actions
        )
        return crypto_config, kwargs

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')

    def get_item(self, **kwargs):
        """Transparently decrypt an item after getting it from the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.get_item
        """
        validate_get_arguments(kwargs)
        crypto_config, ddb_kwargs = self._crypto_config(kwargs['TableName'], **kwargs)
        response = self._client.get_item(**ddb_kwargs)
        if 'Item' in response:
            response['Item'] = decrypt_dynamodb_item(
                item=response['Item'],
                crypto_config=crypto_config
            )
        return response

    def put_item(self, **kwargs):
        """Transparently encrypt an item before putting it to the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.put_item
        """
        crypto_config, ddb_kwargs = self._crypto_config(kwargs['TableName'], **kwargs)
        ddb_kwargs['Item'] = encrypt_dynamodb_item(
            item=ddb_kwargs['Item'],
            crypto_config=crypto_config
        )
        return self._client.put_item(**ddb_kwargs)

    def _encrypted_multi_get_single_table(self, method, **kwargs):
        """Transparently decrypt multiple items after getting them from the table.

        :param method: Method from underlying DynamoDB client object to use
        :type method: callable
        """
        validate_get_arguments(kwargs)
        crypto_config, ddb_kwargs = self._crypto_config(kwargs['TableName'], **kwargs)
        response = method(**ddb_kwargs)
        for pos in range(len(response['Items'])):
            response['Items'][pos] = decrypt_dynamodb_item(
                item=response['Items'][pos],
                crypto_config=crypto_config
            )
        return response

    def query(self, **kwargs):
        """Transparently decrypt multiple items after getting them from a query request to the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.query
        """
        return self._encrypted_multi_get_single_table(self._client.query, **kwargs)

    def scan(self, **kwargs):
        """Transparently decrypt multiple items after getting them from a scan request to the table.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.scan
        """
        return self._encrypted_multi_get_single_table(self._client.scan, **kwargs)

    def batch_get_item(self, **kwargs):
        """Transparently decrypt multiple items after getting them from a batch get item request.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.batch_get_item
        """
        for _table_name, table_kwargs in kwargs['RequestItems'].items():
            validate_get_arguments(table_kwargs)

        request_crypto_config = kwargs.pop('crypto_config', None)

        response = self._client.batch_get_item(**kwargs)
        for table_name, items in response['Responses'].items():
            if request_crypto_config is not None:
                crypto_config = request_crypto_config
            else:
                crypto_config = self._crypto_config(table_name)[0]

            for pos in range(len(items)):
                items[pos] = decrypt_dynamodb_item(
                    item=items[pos],
                    crypto_config=crypto_config
                )
        return response

    def batch_write_item(self, **kwargs):
        """Transparently encrypt multiple items before writing them with a batch write item request.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.batch_write_item
        """
        request_crypto_config = kwargs.pop('crypto_config', None)

        for table_name, items in kwargs['RequestItems'].items():
            if request_crypto_config is not None:
                crypto_config = request_crypto_config
            else:
                crypto_config = self._crypto_config(table_name)[0]

            for pos in range(len(items)):
                for request_type, item in items[pos].items():
                    # We don't encrypt primary indexes, so we can ignore DeleteItem requests
                    if request_type == 'PutRequest':
                        items[pos][request_type]['Item'] = encrypt_dynamodb_item(
                            item=item['Item'],
                            crypto_config=crypto_config
                        )
        return self._client.batch_write_item(**kwargs)
