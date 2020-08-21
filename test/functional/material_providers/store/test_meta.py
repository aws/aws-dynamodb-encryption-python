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
"""Functional tests for ``dynamodb_encryption_sdk.material_providers.store.meta``."""
import pytest

from dynamodb_encryption_sdk.exceptions import NoKnownVersionError
from dynamodb_encryption_sdk.material_providers.store.meta import MetaStore, MetaStoreAttributeNames
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider

from ...functional_test_utils import mock_metastore  # noqa=F401 pylint: disable=unused-import

pytestmark = [pytest.mark.functional, pytest.mark.local]


def test_create_table(mock_metastore):
    # type: (MetaStore) -> None
    assert mock_metastore._table.key_schema == [
        {"AttributeName": MetaStoreAttributeNames.PARTITION.value, "KeyType": "HASH"},
        {"AttributeName": MetaStoreAttributeNames.SORT.value, "KeyType": "RANGE"},
    ]
    assert mock_metastore._table.attribute_definitions == [
        {"AttributeName": MetaStoreAttributeNames.PARTITION.value, "AttributeType": "S"},
        {"AttributeName": MetaStoreAttributeNames.SORT.value, "AttributeType": "N"},
    ]


def test_max_version_empty(mock_metastore):
    # type: (MetaStore) -> None
    with pytest.raises(NoKnownVersionError) as excinfo:
        mock_metastore.max_version("example_name")

    excinfo.match(r"No known version for name: ")


def test_max_version_exists(mock_metastore):
    # type: (MetaStore) -> None
    mock_metastore.get_or_create_provider("example_name", 2)
    mock_metastore.get_or_create_provider("example_name", 5)

    test = mock_metastore.max_version("example_name")

    assert test == 5


@pytest.mark.xfail(strict=True)
def test_version_from_material_description():
    assert False


def test_provider(mock_metastore):
    # type: (MetaStore) -> None
    test = mock_metastore.provider("example_name")

    assert isinstance(test, WrappedCryptographicMaterialsProvider)
