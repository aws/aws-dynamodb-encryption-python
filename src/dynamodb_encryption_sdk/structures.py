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
"""Common structures used by the DynamoDB Encryption Client."""
import copy

import attr
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Iterable, List, Optional, Set, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk.internal.identifiers import ReservedAttributes
from dynamodb_encryption_sdk.internal.validators import dictionary_validator, iterable_validator
from .identifiers import CryptoAction

__all__ = ('EncryptionContext', 'AttributeActions', 'TableIndex', 'TableInfo')


def _validate_attribute_values_are_ddb_items(instance, attribute, value):  # pylint: disable=unused-argument
    """Validate that dictionary values in ``value`` match the structure of DynamoDB JSON
    items.

    .. note::

        We are not trying to validate the full structure of the item with this validator.
        This is just meant to verify that the values roughly match the correct format.
    """
    for data in value.values():
        if len(list(data.values())) != 1:
            raise TypeError('"{}" values do not look like DynamoDB items'.format(attribute.name))


@attr.s(init=False)
class EncryptionContext(object):
    # pylint: disable=too-few-public-methods
    """Additional information about an encryption request.

    :param str table_name: Table name
    :param str partition_key_name: Name of primary index partition attribute
    :param str sort_key_name: Name of primary index sort attribute
    :param dict attributes: Plaintext item attributes as a DynamoDB JSON dictionary
    :param dict material_description: Material description to use with this request
    """

    table_name = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )
    partition_key_name = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )
    sort_key_name = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )
    attributes = attr.ib(
        validator=(
            dictionary_validator(six.string_types, dict),
            _validate_attribute_values_are_ddb_items
        ),
        default=attr.Factory(dict)
    )
    material_description = attr.ib(
        validator=dictionary_validator(six.string_types, six.string_types),
        converter=copy.deepcopy,
        default=attr.Factory(dict)
    )

    def __init__(
            self,
            table_name=None,  # type: Optional[Text]
            partition_key_name=None,  # type: Optional[Text]
            sort_key_name=None,  # type: Optional[Text]
            attributes=None,  # type: Optional[Dict[Text, Dict]]
            material_description=None  # type: Optional[Dict[Text, Text]]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        if attributes is None:
            attributes = {}
        if material_description is None:
            material_description = {}

        self.table_name = table_name
        self.partition_key_name = partition_key_name
        self.sort_key_name = sort_key_name
        self.attributes = attributes
        self.material_description = material_description
        attr.validate(self)


@attr.s(init=False)
class AttributeActions(object):
    """Configuration resource used to determine what action should be taken for a specific attribute.

    :param CryptoAction default_action: Action to take if no specific action is defined in
        ``attribute_actions``
    :param dict attribute_actions: Dictionary mapping attribute names to specific actions
    """

    default_action = attr.ib(
        validator=attr.validators.instance_of(CryptoAction),
        default=CryptoAction.ENCRYPT_AND_SIGN
    )
    attribute_actions = attr.ib(
        validator=dictionary_validator(six.string_types, CryptoAction),
        default=attr.Factory(dict)
    )

    def __init__(
            self,
            default_action=CryptoAction.ENCRYPT_AND_SIGN,  # type: Optional[CryptoAction]
            attribute_actions=None  # type: Optional[Dict[Text, CryptoAction]]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        if attribute_actions is None:
            attribute_actions = {}

        self.default_action = default_action
        self.attribute_actions = attribute_actions
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # () -> None
        """Determine if any actions should ever be taken with this configuration and record that for reference."""
        for attribute in ReservedAttributes:
            if attribute.value in self.attribute_actions:
                raise ValueError('No override behavior can be set for reserved attribute "{}"'.format(attribute.value))

        # Enums are not hashable, but their names are unique
        _unique_actions = set([self.default_action.name])
        _unique_actions.update(set([action.name for action in self.attribute_actions.values()]))
        no_actions = _unique_actions == set([CryptoAction.DO_NOTHING.name])
        self.take_no_actions = no_actions  # attrs confuses pylint: disable=attribute-defined-outside-init

    def action(self, attribute_name):
        # (text) -> CryptoAction
        """Determine the correct :class:`CryptoAction` to apply to a supplied attribute based
        on this config.

        :param str attribute_name: Attribute for which to determine action
        """
        return self.attribute_actions.get(attribute_name, self.default_action)

    def copy(self):
        # () -> AttributeActions
        """Return a new copy of this object."""
        return AttributeActions(
            default_action=self.default_action,
            attribute_actions=self.attribute_actions.copy()
        )

    def set_index_keys(self, *keys):
        """Set the appropriate action for the specified indexed attribute names.

        .. warning::

            If you have already set a custom action for any of these attributes, this will
            raise an error.

        .. code::

            Default Action   -> Index Key Action
            DO_NOTHING       -> DO_NOTHING
            SIGN_ONLY        -> SIGN_ONLY
            ENCRYPT_AND_SIGN -> SIGN_ONLY

        :param str *keys: Attribute names to treat as indexed
        :raises InvalidArgumentError: if a custom action was previously set for any specified
            attributes
        """
        for key in keys:
            index_action = min(self.action(key), CryptoAction.SIGN_ONLY)
            try:
                if self.attribute_actions[key] is not index_action:
                    raise InvalidArgumentError(
                        'Cannot overwrite a previously requested action on indexed attribute: "{}"'.format(key)
                    )
            except KeyError:
                self.attribute_actions[key] = index_action

    def contains_action(self, action):
        # (CryptoAction) -> bool
        """Determine if the specified action is a possible action from this configuration.

        :param CryptoAction action: Action to look for
        """
        return action is self.default_action or action in self.attribute_actions.values()

    def __add__(self, other):
        # (AttributeActions) -> AttributeActions
        """Merge two AttributeActions objects into a new instance, applying the dominant
        action in each discovered case.
        """
        default_action = self.default_action + other.default_action
        all_attributes = set(self.attribute_actions.keys()).union(set(other.attribute_actions.keys()))
        attribute_actions = {}
        for attribute in all_attributes:
            attribute_actions[attribute] = max(self.action(attribute), other.action(attribute))
        return AttributeActions(
            default_action=default_action,
            attribute_actions=attribute_actions
        )


@attr.s(init=False)
class TableIndex(object):
    # pylint: disable=too-few-public-methods
    """Describes a table index.

    :param str partition: Name of the partition attribute
    :param str sort: Name of the sort attribute (optional)
    """

    partition = attr.ib(validator=attr.validators.instance_of(six.string_types))
    sort = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )

    def __init__(
            self,
            partition,  # type: Text
            sort=None  # type: Optional[Text]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.partition = partition
        self.sort = sort
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        """Set the ``attributes`` attribute for ease of access later."""
        self.attributes = set([self.partition])  # attrs confuses pylint: disable=attribute-defined-outside-init
        if self.sort is not None:
            self.attributes.add(self.sort)

    @classmethod
    def from_key_schema(cls, key_schema):
        # type: (Iterable[Dict[Text, Text]]) -> TableIndex
        """Build a TableIndex from the key schema returned by DescribeTable.

        .. code::

            [
                {
                    "KeyType": "HASH"|"RANGE",
                    "AttributeName": ""
                },
            ]

        :param list key_schema: KeySchema from DescribeTable response
        :returns: New TableIndex that describes the provided schema
        :rtype: TableIndex
        """
        index = {
            key['KeyType']: key['AttributeName']
            for key in key_schema
        }
        return cls(
            partition=index['HASH'],
            sort=index.get('RANGE', None)
        )


@attr.s(init=False)
class TableInfo(object):
    """Describes a DynamoDB table.

    :param str name: Table name
    :param bool all_encrypting_secondary_indexes: Should we allow secondary index attributes to be encrypted?
    :param TableIndex primary_index: Description of primary index
    :param secondary_indexes: Set of TableIndex objects describing any secondary indexes
    :type secondary_indexes: list(TableIndex)
    """

    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _primary_index = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(TableIndex)),
        default=None
    )
    _secondary_indexes = attr.ib(
        validator=attr.validators.optional(iterable_validator(list, TableIndex)),
        default=None
    )

    def __init__(
            self,
            name,  # type: Text
            primary_index=None,  # type: Optional[TableIndex]
            secondary_indexes=None  # type: Optional[List[TableIndex]]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.name = name
        self._primary_index = primary_index
        self._secondary_indexes = secondary_indexes
        attr.validate(self)

    @property
    def primary_index(self):
        # type: () -> TableIndex
        """Return the primary TableIndex.

        :returns: primary index description
        :rtype: TableIndex
        :raises AttributeError: if primary index is unknown
        """
        if self._primary_index is None:
            raise AttributeError('Indexes unknown. Run refresh_indexed_attributes')
        return self._primary_index

    @property
    def secondary_indexes(self):
        # type: () -> List[TableIndex]
        """Return the primary TableIndex.

        :returns: secondary index descriptions
        :rtype: TableIndex
        :raises AttributeError: if secondary indexes are unknown
        """
        if self._secondary_indexes is None:
            raise AttributeError('Indexes unknown. Run refresh_indexed_attributes')
        return self._secondary_indexes

    def protected_index_keys(self):
        # type: () -> Set[Text]
        """Provide a set containing the names of all indexed attributes that must not be encrypted."""
        return self.primary_index.attributes

    @property
    def encryption_context_values(self):
        # type: () -> Dict[Text, Text]
        """Build parameters needed to inform an EncryptionContext constructor about this table.

        :rtype: dict
        """
        values = {'table_name': self.name}
        if self.primary_index is not None:
            values.update({
                'partition_key_name': self.primary_index.partition,
                'sort_key_name': self.primary_index.sort
            })
        return values

    def refresh_indexed_attributes(self, client):
        """Use the provided boto3 DynamoDB client to determine all indexes for this table.

        :param client: Pre-configured boto3 DynamoDB client
        :type client: botocore.client.BaseClient
        """
        table = client.describe_table(TableName=self.name)['Table']
        self._primary_index = TableIndex.from_key_schema(table['KeySchema'])

        self._secondary_indexes = []
        for group in ('LocalSecondaryIndexes', 'GlobalSecondaryIndexes'):
            try:
                for index in table[group]:
                    self._secondary_indexes.append(TableIndex.from_key_schema(index['KeySchema']))
            except KeyError:
                pass  # Not all tables will have secondary indexes.
