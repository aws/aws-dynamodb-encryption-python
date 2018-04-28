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
    crypto_config_from_cache, crypto_config_from_kwargs,
    decrypt_batch_get_item, decrypt_get_item, decrypt_multi_get,
    encrypt_batch_write_item, encrypt_put_item, TableInfoCache
)
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions
from .item import decrypt_dynamodb_item, encrypt_dynamodb_item

__all__ = ('EncryptedClient',)


@attr.s
class EncryptedClient(object):
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
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
        self._table_crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_cache,
            self._materials_provider,
            self._attribute_actions,
            self._table_info_cache
        )
        self._item_crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_kwargs,
            self._table_crypto_config
        )
        self.get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_get_item,
            decrypt_dynamodb_item,
            self._item_crypto_config,
            self._client.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item,
            encrypt_dynamodb_item,
            self._item_crypto_config,
            self._client.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_dynamodb_item,
            self._item_crypto_config,
            self._client.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_dynamodb_item,
            self._item_crypto_config,
            self._client.scan
        )
        self.batch_get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_batch_get_item,
            decrypt_dynamodb_item,
            self._table_crypto_config,
            self._client.batch_get_item
        )
        self.batch_write_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_batch_write_item,
            encrypt_dynamodb_item,
            self._table_crypto_config,
            self._client.batch_write_item
        )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided client object.

        :param str name: Attribute name
        :returns: Result of asking the provided client object for that attribute name
        :raises AttributeError: if attribute is not found on provided client object
        """
        return getattr(self._client, name)

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')
