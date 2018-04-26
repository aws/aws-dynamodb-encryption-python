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
"""Tooling for deserializing attributes.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import codecs
from decimal import Decimal
import io
import logging
import struct

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Dict, List, Text, Union  # noqa pylint: disable=unused-import
    from dynamodb_encryption_sdk.internal import dynamodb_types  # noqa pylint: disable=unused-import,ungrouped-imports
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from boto3.dynamodb.types import Binary

from dynamodb_encryption_sdk.exceptions import DeserializationError
from dynamodb_encryption_sdk.identifiers import LOGGER_NAME
from dynamodb_encryption_sdk.internal.formatting.deserialize import decode_byte, decode_length, decode_tag, decode_value
from dynamodb_encryption_sdk.internal.identifiers import Tag, TagValues, TEXT_ENCODING
from dynamodb_encryption_sdk.internal.str_ops import to_str

__all__ = ('deserialize_attribute',)
_LOGGER = logging.getLogger(LOGGER_NAME)


def deserialize_attribute(serialized_attribute):  # noqa: C901 pylint: disable=too-many-locals
    # type: (bytes) -> dynamodb_types.RAW_ATTRIBUTE
    """Deserializes serialized attributes for decryption.

    :param bytes serialized_attribute: Serialized attribute bytes
    :returns: Deserialized attribute
    :rtype: dict
    """

    def _transform_binary_value(value):
        # (bytes) -> bytes
        """Transforms a serialized binary value.

        :param bytes value: Raw deserialized value
        :rtype: bytes
        """
        if isinstance(value, Binary):
            return value.value
        return value

    def _deserialize_binary(stream):
        # type: (io.BytesIO) -> Dict[Text, bytes]
        """Deserializes a binary object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        value = decode_value(stream)
        return {Tag.BINARY.dynamodb_tag: _transform_binary_value(value)}

    def _transform_string_value(value):
        # (bytes) -> dynamodb_types.STRING
        """Transforms a serialized string value.

        :param bytes value: Raw deserialized value
        :rtype: dynamodb_encryption_sdk.internal.dynamodb_types.STRING
        """
        return codecs.decode(value, TEXT_ENCODING)

    def _deserialize_string(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.STRING]
        """Deserializes a string object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        value = decode_value(stream)
        return {Tag.STRING.dynamodb_tag: _transform_string_value(value)}

    def _transform_number_value(value):
        # (bytes) -> dynamodb_types.STRING
        """Transforms a serialized number value.

        :param bytes value: Raw deserialized value
        :rtype: dynamodb_encryption_sdk.internal.dynamodb_types.STRING
        """
        raw_value = codecs.decode(value, TEXT_ENCODING)
        decimal_value = Decimal(to_str(raw_value)).normalize()
        return '{0:f}'.format(decimal_value)

    def _deserialize_number(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.STRING]
        """Deserializes a number object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        value = decode_value(stream)
        return {Tag.NUMBER.dynamodb_tag: _transform_number_value(value)}

    _boolean_map = {
        TagValues.FALSE.value: False,
        TagValues.TRUE.value: True
    }

    def _deserialize_boolean(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.BOOLEAN]
        """Deserializes a boolean object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        value = decode_byte(stream)
        return {Tag.BOOLEAN.dynamodb_tag: _boolean_map[value]}

    def _deserialize_null(stream):  # we want a consistent API but don't use stream, so pylint: disable=unused-argument
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.BOOLEAN]
        """Deserializes a null object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        return {Tag.NULL.dynamodb_tag: True}

    def _deserialize_set(stream, member_transform):
        # type: (io.BytesIO, Callable) -> List[Union[dynamodb_types.BINARY, dynamodb_types.STRING]]
        """Deserializes contents of serialized set.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: list
        """
        member_count = decode_length(stream)
        return sorted([
            member_transform(decode_value(stream))
            for _ in range(member_count)
        ])

    def _deserialize_binary_set(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.SET[dynamodb_types.BINARY]]
        """Deserializes a binary set object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        return {Tag.BINARY_SET.dynamodb_tag: _deserialize_set(stream, _transform_binary_value)}

    def _deserialize_string_set(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.SET[dynamodb_types.STRING]]
        """Deserializes a string set object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        return {Tag.STRING_SET.dynamodb_tag: _deserialize_set(stream, _transform_string_value)}

    def _deserialize_number_set(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.SET[dynamodb_types.STRING]]
        """Deserializes a number set object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        return {Tag.NUMBER_SET.dynamodb_tag: _deserialize_set(stream, _transform_number_value)}

    def _deserialize_list(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.LIST]
        """Deserializes a list object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        member_count = decode_length(stream)
        return {Tag.LIST.dynamodb_tag: [
            _deserialize(stream)
            for _ in range(member_count)
        ]}

    def _deserialize_map(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.MAP]
        """Deserializes a map object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        member_count = decode_length(stream)
        members = {}  # type: dynamodb_types.MAP
        for _ in range(member_count):
            key = _deserialize(stream)
            if Tag.STRING.dynamodb_tag not in key:
                raise DeserializationError(
                    'Malformed serialized map: found "{}" as map key.'.format(list(key.keys())[0])
                )

            value = _deserialize(stream)
            members[key[Tag.STRING.dynamodb_tag]] = value

        return {Tag.MAP.dynamodb_tag: members}

    def _deserialize_function(tag):
        # type: (bytes) -> Callable
        """Identifies the correct deserialization function based on the provided tag.

        :param tag: Identifying tag, read from start of serialized object
        :type tag: dynamodb_encryption_sdk.internal.identifiers.Tag
        :rtype: callable
        """
        deserialize_functions = {
            Tag.BINARY.tag: _deserialize_binary,
            Tag.BINARY_SET.tag: _deserialize_binary_set,
            Tag.NUMBER.tag: _deserialize_number,
            Tag.NUMBER_SET.tag: _deserialize_number_set,
            Tag.STRING.tag: _deserialize_string,
            Tag.STRING_SET.tag: _deserialize_string_set,
            Tag.BOOLEAN.tag: _deserialize_boolean,
            Tag.NULL.tag: _deserialize_null,
            Tag.LIST.tag: _deserialize_list,
            Tag.MAP.tag: _deserialize_map
        }
        try:
            return deserialize_functions[tag]
        except KeyError:
            raise DeserializationError('Unsupported tag: "{}"'.format(tag))

    def _deserialize(stream):
        # type: (io.BytesIO) -> Dict[Text, dynamodb_types.RAW_ATTRIBUTE]
        """Deserializes a serialized object.

        :param stream: Stream containing serialized object
        :type stream: io.BytesIO
        :rtype: dict
        """
        try:
            tag = decode_tag(stream)
            return _deserialize_function(tag)(stream)
        except struct.error:
            raise DeserializationError('Malformed serialized data')

    if not serialized_attribute:
        raise DeserializationError('Empty serialized attribute data')

    stream = io.BytesIO(serialized_attribute)
    return _deserialize(stream)
