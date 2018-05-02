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

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Callable, Dict, Iterator, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

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

__all__ = ('EncryptedClient', 'EncryptedPaginator')


@attr.s(init=False)
class EncryptedPaginator(object):
    """Paginator that decrypts returned items before returning them.

    :param paginator: Pre-configured boto3 DynamoDB paginator object
    :type paginator: botocore.paginate.Paginator
    :param decrypt_method: Item decryptor method from :mod:`dynamodb_encryption_sdk.encrypted.item`
    :param callable crypto_config_method: Callable that returns a :class:`CryptoConfig`
    """

    _paginator = attr.ib(validator=attr.validators.instance_of(botocore.paginate.Paginator))
    _decrypt_method = attr.ib()
    _crypto_config_method = attr.ib(validator=callable_validator)

    def __init__(
            self,
            paginator,  # type: botocore.paginate.Paginator
            decrypt_method,  # type: Callable
            crypto_config_method  # type: Callable
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._paginator = paginator
        self._decrypt_method = decrypt_method
        self._crypto_config_method = crypto_config_method
        attr.validate(self)

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
        # type: (**Any) -> Iterator[Dict]
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


@attr.s(init=False)
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
        accept a ``crypto_config`` parameter, defining a custom :class:`CryptoConfig` instance
        for this request.

    .. warning::

        We do not currently support the ``update_item`` method.

    :param client: Pre-configured boto3 DynamoDB client object
    :type client: boto3.resources.base.BaseClient
    :param CryptographicMaterialsProvider materials_provider: Cryptographic materials provider
        to use
    :param AttributeActions attribute_actions: Table-level configuration of how to encrypt/sign
        attributes
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

    def __init__(
            self,
            client,  # type: botocore.client.BaseClient
            materials_provider,  # type: CryptographicMaterialsProvider
            attribute_actions=None,  # type: Optional[AttributeActions]
            auto_refresh_table_indexes=True,  # type: Optional[bool]
            expect_standard_dictionaries=False  # type: Optional[bool]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        if attribute_actions is None:
            attribute_actions = AttributeActions()

        self._client = client
        self._materials_provider = materials_provider
        self._attribute_actions = attribute_actions
        self._auto_refresh_table_indexes = auto_refresh_table_indexes
        self._expect_standard_dictionaries = expect_standard_dictionaries
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        """Set up the table info cache and translation methods."""
        if self._expect_standard_dictionaries:
            self._encrypt_item = encrypt_python_item  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._decrypt_item = decrypt_python_item  # attrs confuses pylint: disable=attribute-defined-outside-init
        else:
            self._encrypt_item = encrypt_dynamodb_item  # attrs confuses pylint: disable=attribute-defined-outside-init
            self._decrypt_item = decrypt_dynamodb_item  # attrs confuses pylint: disable=attribute-defined-outside-init
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
            self._decrypt_item,
            self._item_crypto_config,
            self._client.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item,
            self._encrypt_item,
            self._item_crypto_config,
            self._client.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            self._decrypt_item,
            self._item_crypto_config,
            self._client.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get,
            self._decrypt_item,
            self._item_crypto_config,
            self._client.scan
        )
        self.batch_get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_batch_get_item,
            self._decrypt_item,
            self._table_crypto_config,
            self._client.batch_get_item
        )
        self.batch_write_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_batch_write_item,
            self._encrypt_item,
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
        """Update item is not yet supported.

        :raises NotImplementedError: if called
        """
        raise NotImplementedError('"update_item" is not yet implemented')

    def get_paginator(self, operation_name):
        """Get a paginator from the underlying client. If the paginator requested is for
        "scan" or "query", the paginator returned will transparently decrypt the returned items.

        :param str operation_name: Name of operation for which to get paginator
        :returns: Paginator for name
        :rtype: :class:`botocore.paginate.Paginator` or :class:`EncryptedPaginator`
        """
        paginator = self._client.get_paginator(operation_name)

        if operation_name in ('scan', 'query'):
            return EncryptedPaginator(
                paginator=paginator,
                decrypt_method=self._decrypt_item,
                crypto_config_method=self._item_crypto_config
            )

        return paginator
