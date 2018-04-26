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
"""Helper functions for serializing values.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import struct

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Sized  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ('encode_length', 'encode_value')


def encode_length(attribute):
    # type: (Sized) -> bytes
    """Encodes the length of the attribute as an unsigned int.

    :param attribute: Attribute with length value
    :returns: Encoded value
    :rtype: bytes
    """
    return struct.pack('>I', len(attribute))


def encode_value(value):
    # type: (bytes) -> bytes
    """Encodes the value in Length-Value format.

    :param value: Value to encode
    :type value: six.string_types or :class:`boto3.dynamodb_encryption_sdk.types.Binary`
    :returns: Length-Value encoded value
    :rtype: bytes
    """
    return struct.pack(
        '>I{attr_len:d}s'.format(attr_len=len(value)),
        len(value),
        value
    )
