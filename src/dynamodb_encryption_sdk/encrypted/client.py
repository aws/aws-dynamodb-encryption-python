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
import botocore.client

from dynamodb_encryption_sdk.internal.utils import (
    decrypt_batch_get_item, decrypt_get_item, decrypt_multi_get,
    encrypt_batch_write_item, encrypt_put_item, TableInfoCache
)
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext
from . import CryptoConfig
from .item import decrypt_dynamodb_item, encrypt_dynamodb_item

__all__ = ('EncryptedClient',)


@attr.s
class EncryptedClient(object):
    # pylint: disable=too-few-public-methods
    """High-level helper class to provide a familiar interface to encrypted tables.

    .. note::

        This class provides a superset of the boto3 DynamoDB client API, so should work as
        a drop-in replacement once configured.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#client

        If you want to provide per-request cryptographic details, the ``put_item``, ``get_item``,
        ``query``, ``scan``, ``batch_write_item``, and ``batch_get_item`` methods will also
        accept a ``crypto_config`` parameter, defining a custom ``CryptoConfig`` instance
        for this request.

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
        """Set up the table info cache and translation methods."""
        self._table_info_cache = TableInfoCache(  # attrs confuses pylint: disable=attribute-defined-outside-init
            client=self._client,
            auto_refresh_table_indexes=self._auto_refresh_table_indexes
        )
        self.get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_get_item,
            decrypt_method=decrypt_dynamodb_item,
            crypto_config_method=self._table_crypto_config,
            read_method=self._client.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item,
            encrypt_method=encrypt_dynamodb_item,
            crypto_config_method=self._table_crypto_config,
            write_method=self._client.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=decrypt_dynamodb_item,
            crypto_config_method=self._table_crypto_config,
            read_method=self._client.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=decrypt_dynamodb_item,
            crypto_config_method=self._table_crypto_config,
            read_method=self._client.scan
        )
        self.batch_get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_batch_get_item,
            decrypt_method=decrypt_dynamodb_item,
            crypto_config_method=self._batch_crypto_config,
            read_method=self._client.batch_get_item
        )
        self.batch_write_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_batch_write_item,
            encrypt_method=encrypt_dynamodb_item,
            crypto_config_method=self._batch_crypto_config,
            write_method=self._client.batch_write_item
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

    def _table_crypto_config(self, **kwargs):
        """Pull all encryption-specific parameters from the request and use them to build
        a crypto config for a single-table operation.

        :returns: crypto config and updated kwargs
        :rtype: dynamodb_encryption_sdk.encrypted.CryptoConfig and dict
        """
        return self._crypto_config(kwargs['TableName'], **kwargs)

    def _batch_crypto_config(self, table_name):
        """Build a crypto config for a specific table.

        :param str table_name: Table for which to build crypto config
        :returns: crypto config
        :rtype: dynamodb_encryption_sdk.encrypted.CryptoConfig
        """
        return self._crypto_config(table_name)[0]

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')
