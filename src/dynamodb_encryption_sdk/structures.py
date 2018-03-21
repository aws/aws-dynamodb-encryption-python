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
import copy

import six

from .identifiers import ItemAction
from dynamodb_encryption_sdk.internal.validators import dictionary_validator, iterable_validator

__all__ = ('EncryptionContext', 'AttributeActions', 'TableIndex', 'TableInfo')


def _validate_attribute_values_are_ddb_items(instance, attribute, value):
    """Validate that dictionary values in ``value`` match the structure of DynamoDB JSON
    items.

    .. note::

        We are not trying to validate the full structure of the item with this validator.
        This is just meant to verify that the values roughly match the correct format.
    """
    for data in value.values():
        if len(list(data.values())) != 1:
            raise TypeError('"{}" values do not look like DynamoDB items'.format(attribute.name))


@attr.s(hash=False)
class EncryptionContext(object):
    """Additional information about an encryption request.

    :param str table_name: Table name
    :param str partition_key_name: Name of primary index partition attribute
    :param str sort_key_name: Name of primary index sort attribute
    :param dict attributes: Plaintext item attributes
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


@attr.s(hash=False)
class AttributeActions(object):
    """Configuration resource used to determine what action should be taken for a specific attribute.

    :param default_action: Action to take if no specific action is defined in ``attribute_actions``
    :type default_action: dynamodb_encryption_sdk.identifiers.ItemAction
    :param dict attribute_actions: Dictionary mapping attribute names to specific actions
    """
    default_action = attr.ib(
        validator=attr.validators.instance_of(ItemAction),
        default=ItemAction.ENCRYPT_AND_SIGN
    )
    attribute_actions = attr.ib(
        validator=dictionary_validator(six.string_types, ItemAction),
        default=attr.Factory(dict)
    )

    def __attrs_post_init__(self):
        # () -> None
        """Determine if any actions should ever be taken with this configuration and record that for reference."""
        # Enums are not hashable, but their names are unique
        _unique_actions = set([self.default_action.name])
        _unique_actions.update(set([action.name for action in self.attribute_actions.values()]))
        self.take_no_actions = _unique_actions == set([ItemAction.DO_NOTHING.name])

    def action(self, attribute_name):
        # (text) -> ItemAction
        """Determines the correct ItemAction to apply to a supplied attribute based on this config."""
        return self.attribute_actions.get(attribute_name, self.default_action)

    def copy(self):
        # () -> AttributeActions
        """Returns a new copy of this object."""
        return AttributeActions(
            default_action=self.default_action,
            attribute_actions=self.attribute_actions.copy()
        )

    def set_index_keys(self, *keys):
        """Sets the appropriate action for the specified indexed attribute names.

        DO_NOTHING -> DO_NOTHING
        SIGN_ONLY -> SIGN_ONLY
        ENCRYPT_AND_SIGN -> SIGN_ONLY
        """
        for key in keys:
            current_action = self.action(key)
            self.attribute_actions[key] = min(current_action, ItemAction.SIGN_ONLY)

    def __add__(self, other):
        # (AttributeActions) -> AttributeActions
        """Merges two AttributeActions objects into a new instance, applying the dominant
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


@attr.s(hash=False)
class TableIndex(object):
    """Describes a table index.

    :param str partition: Name of the partition attribute
    :param str sort: Name of the sort attribute (optional)
    """
    partition = attr.ib(validator=attr.validators.instance_of(six.string_types))
    sort = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )

    def __attrs_post_init__(self):
        """Set the ``attributes`` attribute for ease of access later."""
        self.attributes = set([self.partition])
        if self.sort is None:
            self.attributes.add(self.sort)


@attr.s(hash=False)
class TableInfo(object):
    """Description of a DynamoDB table.

    :param str name: Table name
    :param bool all_encrypting_secondary_indexes: Should we allow secondary index attributes to be encrypted?
    :param primary_index: Description of primary index
    :type primary_index: dynamodb_encryption_sdk.structures.TableIndex
    :param indexed_attributes: Listing of all indexes attribute names
    :type indexed_attributes: set of str
    """
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    allow_encrypting_secondary_indexes = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=False
    )
    _primary_index = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(TableIndex)),
        default=None
    )
    _indexed_attributes = attr.ib(
        validator=attr.validators.optional(iterable_validator(set, six.string_types)),
        default=None
    )

    @property
    def primary_index(self):
        # type: () -> TableIndex
        """"""
        if self._primary_index is None:
            raise Exception('TODO:Indexes unknown. Run refresh_indexed_attributes')
        return self._primary_index

    @property
    def indexed_attributes(self):
        # type: () -> TableIndex
        # TODO: Think about merging this and all_index_keys
        """"""
        if self._indexed_attributes is None:
            raise Exception('TODO:Indexes unknown. Run refresh_indexed_attributes')
        return self._indexed_attributes

    def all_index_keys(self):
        # type: () -> Set[str]
        """Provide a set containing the names of all indexed attributes that must not be encrypted."""
        if self._primary_index is None:
            return set()

        if self.allow_encrypting_secondary_indexes:
            return self.primary_index.attributes

        return self.indexed_attributes

    def refresh_indexed_attributes(self, client):
        """Use the provided boto3 DynamoDB client to determine all indexes for this table.

        :param client: Pre-configured boto3 DynamoDB client
        :type client: TODO:
        """
        table = client.describe_table(TableName=self.name)['Table']
        primary_index = {
            key['KeyType']: key['AttributeName']
            for key in table['KeySchema']
        }
        indexed_attributes = set(primary_index.values())
        self._primary_index = TableIndex(
            partition=primary_index['HASH'],
            sort=primary_index.get('RANGE', None)
        )
        for group in ('LocalSecondaryIndexes', 'GlobalSecondaryIndexes'):
            try:
                for index in table[group]:
                    indexed_attributes.update(set([
                        key['AttributeName'] for key in index['KeySchema']
                    ]))
            except KeyError:
                pass  # Not all tables will have secondary indexes.
        self._indexed_attributes = indexed_attributes
