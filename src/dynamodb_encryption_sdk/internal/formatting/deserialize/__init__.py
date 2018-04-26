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
"""Helper functions for deserializing values.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import struct

from dynamodb_encryption_sdk.exceptions import DeserializationError

__all__ = ('unpack_value', 'decode_length', 'decode_value', 'decode_tag')


def unpack_value(format_string, stream):
    """Helper function to unpack struct data from a stream and update the signature verifier.

    :param str format_string: Struct format string
    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Unpacked values
    :rtype: tuple
    """
    message_bytes = stream.read(struct.calcsize(format_string))
    return struct.unpack(format_string, message_bytes)


def decode_length(stream):
    """Decode the length of a value from a serialized stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Decoded length
    :rtype: int
    """
    (value,) = unpack_value('>I', stream)
    return value


def decode_value(stream):
    """Decode the contents of a value from a serialized stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Decoded value
    :rtype: bytes
    """
    length = decode_length(stream)
    (value,) = unpack_value('>{:d}s'.format(length), stream)
    return value


def decode_byte(stream):
    """Decode a single raw byte from a serialized stream (used for deserialize bool).

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Decoded value
    :rtype: bytes
    """
    (value,) = unpack_value('>1s', stream)
    return value


def decode_tag(stream):
    """Decode a tag value from a serialized stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Decoded tag
    :rtype: bytes
    """
    (reserved, tag) = unpack_value('>cc', stream)

    if reserved != b'\x00':
        raise DeserializationError('Invalid tag: reserved byte is not null')

    return tag
