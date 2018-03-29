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
"""Otherwise undifferentiated utility resources."""
import attr
import botocore.client

from dynamodb_encryption_sdk.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk.internal.str_ops import to_bytes
from dynamodb_encryption_sdk.structures import TableInfo

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Dict, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = (
    'sorted_key_map', 'TableInfoCache',
    'decrypt_get_item', 'decrypt_multi_get', 'decrypt_batch_get_item',
    'encrypt_put_item', 'encrypt_batch_write_item'
)


def sorted_key_map(item, transform=to_bytes):
    """Creates a list of the item's key/value pairs as tuples, sorted by the keys transformed by transform.

    :param dict item: Source dictionary
    :param function transform: Transform function
    :returns: List of tuples containing transformed key, original value, and original key for each entry
    :rtype: list of tuples
    """
    sorted_items = []
    for key, value in item.items():
        _key = transform(key)
        sorted_items.append((_key, value, key))
    sorted_items = sorted(sorted_items, key=lambda x: x[0])
    return sorted_items


@attr.s
class TableInfoCache(object):
    # pylint: disable=too-few-public-methods
    """Very simple cache of TableInfo objects, providing configuration information about DynamoDB tables.

    :param client: Boto3 DynamoDB client
    :type client: botocore.client.BaseClient
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table.
    """

    _client = attr.ib(validator=attr.validators.instance_of(botocore.client.BaseClient))
    _auto_refresh_table_indexes = attr.ib(validator=attr.validators.instance_of(bool))

    def __attrs_post_init__(self):
        """Set up the empty cache."""
        self._all_tables_info = {}  # type: Dict[Text, TableInfo]  # pylint: disable=attribute-defined-outside-init

    def table_info(self, table_name):
        """Collect a TableInfo object for the specified table, creating and adding it to
        the cache if not already present.

        :param str table_name: Name of table
        :returns: TableInfo describing the requested table
        :rtype: dynamodb_encryption_sdk.structures.TableInfo
        """
        try:
            return self._all_tables_info[table_name]
        except KeyError:
            _table_info = TableInfo(name=table_name)
            if self._auto_refresh_table_indexes:
                _table_info.refresh_indexed_attributes(self._client)
            self._all_tables_info[table_name] = _table_info
            return _table_info


def validate_get_arguments(kwargs):
    # type: (Dict[Text, Any]) -> None
    """Verify that attribute filtering parameters are not found in the request.

    :raises InvalidArgumentError: if banned parameters are found
    """
    for arg in ('AttributesToGet', 'ProjectionExpression'):
        if arg in kwargs:
            raise InvalidArgumentError('"{}" is not supported for this operation'.format(arg))

    if kwargs.get('Select', None) in ('SPECIFIC_ATTRIBUTES', 'ALL_PROJECTED_ATTRIBUTES', 'SPECIFIC_ATTRIBUTES'):
        raise InvalidArgumentError('Scan "Select" value of "{}" is not supported'.format(kwargs['Select']))


def decrypt_multi_get(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # TODO: narrow this down
    """Transparently decrypt multiple items after getting them from the table.

    :param callable decrypt_method: Method to use to decrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a ``CryptoConfig``
    :param callable read_method: Method that reads from the table
    """
    validate_get_arguments(kwargs)
    crypto_config, ddb_kwargs = crypto_config_method(**kwargs)
    response = read_method(**ddb_kwargs)
    for pos in range(len(response['Items'])):
        response['Items'][pos] = decrypt_method(
            item=response['Items'][pos],
            crypto_config=crypto_config
        )
    return response


def decrypt_get_item(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # TODO: narrow this down
    """Transparently decrypt an item after getting it from the table.

    :param callable decrypt_method: Method to use to decrypt item
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a ``CryptoConfig``
    :param callable read_method: Method that reads from the table
    """
    validate_get_arguments(kwargs)
    crypto_config, ddb_kwargs = crypto_config_method(**kwargs)
    response = read_method(**ddb_kwargs)
    if 'Item' in response:
        response['Item'] = decrypt_method(
            item=response['Item'],
            crypto_config=crypto_config
        )
    return response


def decrypt_batch_get_item(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # TODO: narrow this down
    """Transparently decrypt multiple items after getting them in a batch request.

    :param callable decrypt_method: Method to use to decrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a ``CryptoConfig``
    :param callable read_method: Method that reads from the table
    """
    request_crypto_config = kwargs.pop('crypto_config', None)

    for _table_name, table_kwargs in kwargs['RequestItems'].items():
        validate_get_arguments(table_kwargs)

    response = read_method(**kwargs)
    for table_name, items in response['Responses'].items():
        if request_crypto_config is not None:
            crypto_config = request_crypto_config
        else:
            crypto_config = crypto_config_method(table_name)

        for pos, value in enumerate(items):
            items[pos] = decrypt_method(
                item=value,
                crypto_config=crypto_config
            )
    return response


def encrypt_put_item(encrypt_method, crypto_config_method, write_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # TODO: narrow this down
    """Transparently encrypt an item before putting it to the table.

    :param callable encrypt_method: Method to use to encrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a ``CryptoConfig``
    :param callable read_method: Method that reads from the table
    """
    crypto_config, ddb_kwargs = crypto_config_method(**kwargs)
    ddb_kwargs['Item'] = encrypt_method(
        item=ddb_kwargs['Item'],
        crypto_config=crypto_config
    )
    return write_method(**ddb_kwargs)


def encrypt_batch_write_item(encrypt_method, crypto_config_method, write_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # TODO: narrow this down
    """Transparently encrypt multiple items before putting them in a batch request.

    :param callable encrypt_method: Method to use to encrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a ``CryptoConfig``
    :param callable read_method: Method that reads from the table
    """
    request_crypto_config = kwargs.pop('crypto_config', None)

    for table_name, items in kwargs['RequestItems'].items():
        if request_crypto_config is not None:
            crypto_config = request_crypto_config
        else:
            crypto_config = crypto_config_method(table_name)

        for pos, value in enumerate(items):
            for request_type, item in value.items():
                # We don't encrypt primary indexes, so we can ignore DeleteItem requests
                if request_type == 'PutRequest':
                    items[pos][request_type]['Item'] = encrypt_method(
                        item=item['Item'],
                        crypto_config=crypto_config
                    )
    return write_method(**kwargs)
