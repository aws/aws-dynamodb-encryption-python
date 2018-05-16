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
"""Functional tests for ``dynamodb_encryption_sdk.material_providers.most_recent``."""
from mock import MagicMock, sentinel
import pytest

from dynamodb_encryption_sdk.material_providers.most_recent import MostRecentProvider
from dynamodb_encryption_sdk.material_providers.store import ProviderStore

pytestmark = [pytest.mark.functional, pytest.mark.local]


def test_failed_lock_acquisition():
    store = MagicMock(__class__=ProviderStore)
    provider = MostRecentProvider(
        provider_store=store,
        material_name='my material',
        version_ttl=10.0
    )
    provider._version = 9
    provider._cache.put(provider._version, sentinel.nine)

    with provider._lock:
        test = provider._get_most_recent_version(allow_local=True)

    assert test is sentinel.nine
    assert not store.mock_calls
