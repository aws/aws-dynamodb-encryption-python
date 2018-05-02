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
"""Tooling for serializing attributes.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import io
import logging

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable  # noqa pylint: disable=unused-import
    from dynamodb_encryption_sdk.internal import dynamodb_types  # noqa pylint: disable=unused-import,ungrouped-imports
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from boto3.dynamodb.types import Binary, DYNAMODB_CONTEXT

from dynamodb_encryption_sdk.exceptions import SerializationError
from dynamodb_encryption_sdk.identifiers import LOGGER_NAME
from dynamodb_encryption_sdk.internal.formatting.serialize import encode_length, encode_value
from dynamodb_encryption_sdk.internal.identifiers import Tag, TagValues
from dynamodb_encryption_sdk.internal.str_ops import to_bytes

__all__ = ('serialize_attribute',)
_LOGGER = logging.getLogger(LOGGER_NAME)
_RESERVED = b'\x00'


def _sorted_key_map(item, transform=to_bytes):
    """Creates a list of the item's key/value pairs as tuples, sorted by the keys transformed by transform.

    :param dict item: Source dictionary
    :param function transform: Transform function
    :returns: List of tuples containing transformed key, original value, and original key for each entry
    :rtype: list(tuple)
    """
    sorted_items = []
    for key, value in item.items():
        _key = transform(key)
        sorted_items.append((_key, value, key))
    sorted_items = sorted(sorted_items, key=lambda x: x[0])
    return sorted_items


def serialize_attribute(attribute):  # noqa: C901 pylint: disable=too-many-locals
    # type: (dynamodb_types.RAW_ATTRIBUTE) -> bytes
    """Serializes a raw attribute to a byte string as defined for the DynamoDB Client-Side Encryption Standard.

    :param dict attribute: Item attribute value
    :returns: Serialized attribute
    :rtype: bytes
    """

    def _transform_binary_value(value):
        # type: (dynamodb_types.BINARY) -> bytes
        """
        :param value: Input value
        :type value: boto3.dynamodb.types.Binary
        :returns: bytes value
        :rtype: bytes
        """
        if isinstance(value, Binary):
            return bytes(value.value)
        return bytes(value)

    def _serialize_binary(_attribute):
        # type: (dynamodb_types.BINARY) -> bytes
        """
        :param _attribute: Attribute to serialize
        :type _attribute: boto3.dynamodb.types.Binary
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _RESERVED + Tag.BINARY.tag + encode_value(_transform_binary_value(_attribute))

    def _transform_number_value(value):
        # type: (str) -> bytes
        """
        :param value: Input value
        :type value: numbers.Number
        :returns: bytes value
        :rtype: bytes
        """
        # At this point we are receiving values which have already been transformed
        # by dynamodb.TypeSerializer, so all numbers are str. However, TypeSerializer
        # leaves trailing zeros if they are defined in the Decimal call, but we need to
        # strip all trailing zeros.
        decimal_value = DYNAMODB_CONTEXT.create_decimal(value).normalize()
        return '{0:f}'.format(decimal_value).encode('utf-8')

    def _serialize_number(_attribute):
        # type: (str) -> bytes
        """
        :param _attribute: Attribute to serialize
        :type _attribute: numbers.Number
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _RESERVED + Tag.NUMBER.tag + encode_value(_transform_number_value(_attribute))

    def _transform_string_value(value):
        # type: (dynamodb_types.STRING) -> bytes
        """
        :param value: Input value
        :type value: bytes or str
        :returns: bytes value
        :rtype: bytes
        """
        return to_bytes(value)

    def _serialize_string(_attribute):
        # type: (dynamodb_types.STRING) -> bytes
        """
        :param _attribute: Attribute to serialize
        :type _attribute: six.string_types
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _RESERVED + Tag.STRING.tag + encode_value(_transform_string_value(_attribute))

    def _serialize_boolean(_attribute):
        # type: (dynamodb_types.BOOLEAN) -> bytes
        """
        :param bool _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        _attribute_value = TagValues.TRUE.value if _attribute else TagValues.FALSE.value
        return _RESERVED + Tag.BOOLEAN.tag + _attribute_value

    def _serialize_null(_attribute):
        # type: (dynamodb_types.NULL) -> bytes
        """
        :param _attribute: Attribute to serialize
        :type _attribute: types.NoneType
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _RESERVED + Tag.NULL.tag

    def _serialize_set(tag, _attribute, member_function):
        # type: (Tag, dynamodb_types.SET[dynamodb_types.ATTRIBUTE], Callable) -> bytes
        """
        :param bytes tag: Tag to identify this set
        :param set _attribute: Attribute to serialize
        :param member_function: Serialization function for members
        :returns: Serialized _attribute
        :rtype: bytes
        """
        serialized_attribute = io.BytesIO()
        serialized_attribute.write(_RESERVED)
        serialized_attribute.write(tag.tag)
        serialized_attribute.write(encode_length(_attribute))

        encoded_members = []
        for member in _attribute:
            encoded_members.append(member_function(member))
        for member in sorted(encoded_members):
            serialized_attribute.write(encode_value(member))

        return serialized_attribute.getvalue()

    def _serialize_binary_set(_attribute):
        # type: (dynamodb_types.SET[dynamodb_types.ATTRIBUTE]) -> bytes
        """
        :param set _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _serialize_set(Tag.BINARY_SET, _attribute, _transform_binary_value)

    def _serialize_number_set(_attribute):
        # type: (dynamodb_types.SET[dynamodb_types.ATTRIBUTE]) -> bytes
        """
        :param set _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _serialize_set(Tag.NUMBER_SET, _attribute, _transform_number_value)

    def _serialize_string_set(_attribute):
        # type: (dynamodb_types.SET[dynamodb_types.ATTRIBUTE]) -> bytes
        """
        :param set _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        return _serialize_set(Tag.STRING_SET, _attribute, _transform_string_value)

    def _serialize_list(_attribute):
        # type: (dynamodb_types.LIST) -> bytes
        """
        :param list _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        serialized_attribute = io.BytesIO()
        serialized_attribute.write(_RESERVED)
        serialized_attribute.write(Tag.LIST.tag)
        serialized_attribute.write(encode_length(_attribute))
        for member in _attribute:
            serialized_attribute.write(serialize_attribute(member))

        return serialized_attribute.getvalue()

    def _serialize_map(_attribute):
        # type: (dynamodb_types.MAP) -> bytes
        """
        :param list _attribute: Attribute to serialize
        :returns: Serialized _attribute
        :rtype: bytes
        """
        serialized_attribute = io.BytesIO()
        serialized_attribute.write(_RESERVED)
        serialized_attribute.write(Tag.MAP.tag)
        serialized_attribute.write(encode_length(_attribute))

        sorted_items = _sorted_key_map(
            item=_attribute,
            transform=_transform_string_value
        )

        for key, value, _original_key in sorted_items:
            serialized_attribute.write(_serialize_string(key))
            serialized_attribute.write(serialize_attribute(value))

        return serialized_attribute.getvalue()

    def _serialize_function(dynamodb_tag):
        # type: (str) -> Callable[[dynamodb_types.ATTRIBUTE], bytes]
        """Locates the appropriate serialization function for the specified DynamoDB attribute tag."""
        serialize_functions = {
            Tag.BINARY.dynamodb_tag: _serialize_binary,
            Tag.BINARY_SET.dynamodb_tag: _serialize_binary_set,
            Tag.NUMBER.dynamodb_tag: _serialize_number,
            Tag.NUMBER_SET.dynamodb_tag: _serialize_number_set,
            Tag.STRING.dynamodb_tag: _serialize_string,
            Tag.STRING_SET.dynamodb_tag: _serialize_string_set,
            Tag.BOOLEAN.dynamodb_tag: _serialize_boolean,
            Tag.NULL.dynamodb_tag: _serialize_null,
            Tag.LIST.dynamodb_tag: _serialize_list,
            Tag.MAP.dynamodb_tag: _serialize_map
        }
        try:
            return serialize_functions[dynamodb_tag]
        except KeyError:
            raise SerializationError('Unsupported DynamoDB data type: "{}"'.format(dynamodb_tag))

    if not isinstance(attribute, dict):
        raise TypeError('Invalid attribute type "{}": must be dict'.format(type(attribute)))

    if len(attribute) != 1:
        raise SerializationError('cannot serialize attribute: incorrect number of members {} != 1'.format(
            len(attribute)
        ))
    key, value = list(attribute.items())[0]
    return _serialize_function(key)(value)
