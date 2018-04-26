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
"""Helper functions for consistently obtaining str and bytes objects in both Python2 and Python3.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import codecs

import six

from dynamodb_encryption_sdk.internal.identifiers import TEXT_ENCODING

__all__ = ('to_str', 'to_bytes')


def to_str(data):
    """Takes an input str or bytes object and returns an equivalent str object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to str
    :rtype: str
    """
    if isinstance(data, bytes):
        return codecs.decode(data, TEXT_ENCODING)
    return data


def to_bytes(data):
    """Takes an input str or bytes object and returns an equivalent bytes object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to bytes
    :rtype: bytes
    """
    if isinstance(data, six.string_types) and not isinstance(data, bytes):
        return codecs.encode(data, TEXT_ENCODING)
    return data
