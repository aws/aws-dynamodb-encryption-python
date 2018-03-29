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

from dynamodb_encryption_sdk.internal.utils import (
    crypto_config_from_kwargs, crypto_config_from_table_info,
    decrypt_get_item, decrypt_multi_get, encrypt_put_item
)
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, TableInfo
from .item import decrypt_python_item, encrypt_python_item

__all__ = ('EncryptedTable',)


@attr.s
class EncryptedTable(object):
    # pylint: disable=too-few-public-methods
    """High-level helper class to provide a familiar interface to encrypted tables.

    .. note::

        This class provides a superset of the boto3 DynamoDB Table API, so should work as
        a drop-in replacement once configured.

        https://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#table

        If you want to provide per-request cryptographic details, the ``put_item``, ``get_item``,
        ``query``, and ``scan`` methods will also accept a ``crypto_config`` parameter, defining
        a custom ``CryptoConfig`` instance for this request.

    .. warning::

        We do not currently support the ``update_item`` method.

    :param table: Pre-configured boto3 DynamoDB Table object
    :type table: boto3.resources.base.ServiceResource
    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param table_info: Information about the target DynamoDB table
    :type table_info: dynamodb_encryption_sdk.structures.TableInfo
    :param attribute_actions: Table-level configuration of how to encrypt/sign attributes
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table. (default: True)
    """

    _table = attr.ib(validator=attr.validators.instance_of(ServiceResource))
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    _table_info = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(TableInfo)),
        default=None
    )
    _attribute_actions = attr.ib(
        validator=attr.validators.instance_of(AttributeActions),
        default=attr.Factory(AttributeActions)
    )
    _auto_refresh_table_indexes = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=True
    )

    def __attrs_post_init__(self):
        """Prepare table info is it was not set and set up translation methods."""
        if self._table_info is None:
            self._table_info = TableInfo(name=self._table.name)

        if self._auto_refresh_table_indexes:
            self._table_info.refresh_indexed_attributes(self._table.meta.client)

        # Clone the attribute actions before we modify them
        self._attribute_actions = self._attribute_actions.copy()
        self._attribute_actions.set_index_keys(*self._table_info.protected_index_keys())

        self._crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_kwargs,
            fallback=partial(
                crypto_config_from_table_info,
                materials_provider=self._materials_provider,
                attribute_actions=self._attribute_actions,
                table_info=self._table_info
            )
        )
        self.get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_get_item,
            decrypt_method=decrypt_python_item,
            crypto_config_method=self._crypto_config,
            read_method=self._table.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item,
            encrypt_method=encrypt_python_item,
            crypto_config_method=self._crypto_config,
            write_method=self._table.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=decrypt_python_item,
            crypto_config_method=self._crypto_config,
            read_method=self._table.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=decrypt_python_item,
            crypto_config_method=self._crypto_config,
            read_method=self._table.scan
        )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided bridge object.

        :param str name: Attribute name
        :returns: Result of asking the provided table object for that attribute name
        :raises AttributeError: if attribute is not found on provided bridge object
        """
        return getattr(self._table, name)

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')
