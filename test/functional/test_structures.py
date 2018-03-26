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
import pytest

from dynamodb_encryption_sdk.structures import TableIndex

pytestmark = [pytest.mark.functional, pytest.mark.local]


@pytest.mark.parametrize('kwargs, expected_attributes', (
    (dict(partition='partition_name'), set(['partition_name'])),
    (dict(partition='partition_name', sort='sort_name'), set(['partition_name', 'sort_name']))
))
def test_tableindex_attributes(kwargs, expected_attributes):
    index = TableIndex(**kwargs)
    assert index.attributes == expected_attributes


@pytest.mark.parametrize('key_schema, expected_kwargs', (
    (
        [
            {
                'KeyType': 'HASH',
                'AttributeName': 'partition_name'
            }
        ],
        dict(partition='partition_name')
    ),
    (
        [
            {
                'KeyType': 'HASH',
                'AttributeName': 'partition_name'
            },
            {
                'KeyType': 'RANGE',
                'AttributeName': 'sort_name'
            }
        ],
        dict(partition='partition_name', sort='sort_name')
    )
))
def test_tableindex_from_key_schema(key_schema, expected_kwargs):
    index = TableIndex.from_key_schema(key_schema)
    expected_index = TableIndex(**expected_kwargs)

    assert index == expected_index
