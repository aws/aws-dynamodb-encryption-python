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
"""Integration tests for ``dynamodb_encryption_sdk.material_providers.store.meta``."""
import pytest

from dynamodb_encryption_sdk.exceptions import NoKnownVersionError
from dynamodb_encryption_sdk.material_providers.store.meta import MetaStore, MetaStoreAttributeNames

from ...integration_test_utils import temp_metastore  # noqa=F401 pylint: disable=unused-import

pytestmark = [pytest.mark.integ, pytest.mark.ddb_integ]


def test_max_version_empty(temp_metastore):
    # type: (MetaStore) -> None
    with pytest.raises(NoKnownVersionError) as excinfo:
        temp_metastore.max_version("example_name")

    excinfo.match(r"No known version for name: ")


def test_max_version_exists(temp_metastore):
    # type: (MetaStore) -> None
    temp_metastore.get_or_create_provider("example_name", 2)
    temp_metastore.get_or_create_provider("example_name", 5)

    test = temp_metastore.max_version("example_name")

    assert test == 5


def test_get_or_create_provider_new_version(temp_metastore):
    # type: (MetaStore) -> None
    with pytest.raises(NoKnownVersionError):
        temp_metastore.max_version("example_name")

    temp_metastore.get_or_create_provider("example_name", 5)

    test = temp_metastore.max_version("example_name")

    assert test == 5


def test_get_or_create_provider_existing_version(temp_metastore):
    # type: (MetaStore) -> None
    # create version
    temp_metastore.get_or_create_provider("example_name", 5)

    # retrieve version
    temp_metastore.get_or_create_provider("example_name", 5)

    test = temp_metastore.max_version("example_name")

    assert test == 5


def test_get_or_create_provider_no_overwrite(temp_metastore):
    # type: (MetaStore) -> None
    # create version
    provider_1 = temp_metastore.get_or_create_provider("example_name", 5)

    initial_item = temp_metastore._table.get_item(
        Key={MetaStoreAttributeNames.PARTITION.value: "example_name", MetaStoreAttributeNames.SORT.value: 5}
    )["Item"]

    # retrieve version
    provider_2 = temp_metastore.get_or_create_provider("example_name", 5)

    assert provider_1 == provider_2

    second_item = temp_metastore._table.get_item(
        Key={MetaStoreAttributeNames.PARTITION.value: "example_name", MetaStoreAttributeNames.SORT.value: 5}
    )["Item"]

    assert initial_item == second_item
