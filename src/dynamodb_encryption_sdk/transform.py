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
"""Helper tools for translating between native and DynamoDB items."""
from typing import Any, Dict

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

__all__ = ("dict_to_ddb", "ddb_to_dict")


def dict_to_ddb(item):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    # narrow these types down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Converts a native Python dictionary to a raw DynamoDB item.

    :param dict item: Native item
    :returns: DynamoDB item
    :rtype: dict
    """
    serializer = TypeSerializer()
    return {key: serializer.serialize(value) for key, value in item.items()}


def ddb_to_dict(item):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    # narrow these types down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Converts a raw DynamoDB item to a native Python dictionary.

    :param dict item: DynamoDB item
    :returns: Native item
    :rtype: dict
    """
    deserializer = TypeDeserializer()
    return {key: deserializer.deserialize(value) for key, value in item.items()}
