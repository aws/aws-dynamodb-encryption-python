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
import botocore

from dynamodb_encryption_sdk.internal.utils import (
    crypto_config_from_cache, crypto_config_from_kwargs,
    decrypt_batch_get_item, decrypt_get_item, decrypt_multi_get,
    encrypt_batch_write_item, encrypt_put_item, TableInfoCache,
    validate_get_arguments
)
from dynamodb_encryption_sdk.internal.validators import callable_validator
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions
from .item import decrypt_dynamodb_item, decrypt_python_item, encrypt_dynamodb_item, encrypt_python_item

__all__ = ('EncryptedClient',)


@attr.s
class EncryptedPaginator(object):
    """Paginator that decrypts returned items before returning them.

    :param paginator: Pre-configured boto3 DynamoDB paginator object
    :type paginator: botocore.paginate.Paginator
    :param decrypt_method: Item decryptor method from ``dynamodb_encryption_sdk.encrypted.item``
    :param callable crypto_config_method: Callable that returns a crypto config
    """

    _paginator = attr.ib(validator=attr.validators.instance_of(botocore.paginate.Paginator))
    _decrypt_method = attr.ib()
    _crypto_config_method = attr.ib(validator=callable_validator)

    @_decrypt_method.validator
    def validate_decrypt_method(self, attribute, value):
        # pylint: disable=unused-argument
        """Validate that _decrypt_method is one of the item encryptors."""
        if self._decrypt_method not in (decrypt_python_item, decrypt_dynamodb_item):
            raise ValueError(
                '"{name}" must be an item decryptor from dynamodb_encryption_sdk.encrypted.item'.format(
                    name=attribute.name
                )
            )

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided client object.

        :param str name: Attribute name
        :returns: Result of asking the provided client object for that attribute name
        :raises AttributeError: if attribute is not found on provided client object
        """
        return getattr(self._paginator, name)

    def paginate(self, **kwargs):
        # type: (**Any) -> Dict
        # TODO: narrow this down
        """Create an iterator that will paginate through responses from the underlying paginator,
        transparently decrypting any returned items.
        """
        validate_get_arguments(kwargs)

        crypto_config, ddb_kwargs = self._crypto_config_method(**kwargs)

        for page in self._paginator.paginate(**ddb_kwargs):
            for pos, value in enumerate(page['Items']):
                page['Items'][pos] = self._decrypt_method(
                    item=value,
                    crypto_config=crypto_config
                )
            yield page


@attr.s
class EncryptedClient(object):
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """High-level helper class to provide a familiar interface to encrypted tables.

    >>> import boto3
    >>> from dynamodb_encryption_sdk.encrypted.client import EncryptedClient
    >>> from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider
    >>> client = boto3.client('dynamodb')
    >>> aws_kms_cmp = AwsKmsCryptographicMaterialsProvider('alias/MyKmsAlias')
    >>> encrypted_client = EncryptedClient(
    ...     client=client,
    ...     materials_provider=aws_kms_cmp
    ... )

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

    :param table: Pre-configured boto3 DynamoDB client object
    :type table: boto3.resources.base.BaseClient
    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param attribute_actions: Table-level configuration of how to encrypt/sign attributes
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table. (default: True)
    :param bool expect_standard_dictionaries: Should we expect items to be standard Python
        dictionaries? This should only be set to True if you are using a client obtained
        from a service resource or table resource (ex: ``table.meta.client``). (default: False)
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
    _expect_standard_dictionaries = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=False
    )

    def __attrs_post_init__(self):
        """Set up the table info cache and translation methods."""
        if self._expect_standard_dictionaries:
            self._encrypt_item = encrypt_python_item
            self._decrypt_item = decrypt_python_item
        else:
            self._encrypt_item = encrypt_dynamodb_item
            self._decrypt_item = decrypt_dynamodb_item
        self._table_info_cache = TableInfoCache(  # attrs confuses pylint: disable=attribute-defined-outside-init
            client=self._client,
            auto_refresh_table_indexes=self._auto_refresh_table_indexes
        )
        self._table_crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_cache,
            materials_provider=self._materials_provider,
            attribute_actions=self._attribute_actions,
            table_info_cache=self._table_info_cache
        )
        self._item_crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_kwargs,
            fallback=self._table_crypto_config
        )
        self.get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_get_item,
            decrypt_method=self._decrypt_item,
            crypto_config_method=self._item_crypto_config,
            read_method=self._client.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item,
            encrypt_method=self._encrypt_item,
            crypto_config_method=self._item_crypto_config,
            write_method=self._client.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=self._decrypt_item,
            crypto_config_method=self._item_crypto_config,
            read_method=self._client.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            decrypt_method=self._decrypt_item,
            crypto_config_method=self._item_crypto_config,
            read_method=self._client.scan
        )
        self.batch_get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_batch_get_item,
            decrypt_method=self._decrypt_item,
            crypto_config_method=self._table_crypto_config,
            read_method=self._client.batch_get_item
        )
        self.batch_write_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_batch_write_item,
            encrypt_method=self._encrypt_item,
            crypto_config_method=self._table_crypto_config,
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

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')

    def get_paginator(self, operation_name):
        """"""
        paginator = self._client.get_paginator(operation_name)

        if operation_name in ('scan', 'query'):
            return EncryptedPaginator(
                paginator=paginator,
                decrypt_method=self._decrypt_item,
                crypto_config_method=self._item_crypto_config
            )

        return paginator
