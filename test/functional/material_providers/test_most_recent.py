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
from collections import defaultdict

import pytest
from mock import MagicMock, sentinel

from dynamodb_encryption_sdk.exceptions import NoKnownVersionError
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.most_recent import MostRecentProvider
from dynamodb_encryption_sdk.material_providers.store import ProviderStore

pytestmark = [pytest.mark.functional, pytest.mark.local]


class SentinelCryptoMaterialsProvider(CryptographicMaterialsProvider):
    def __init__(self, name, version):
        self.name = name
        self.version = version
        self._material_description = version
        self.provider_calls = []

    def encryption_materials(self, encryption_context):
        self.provider_calls.append(("encryption_materials", encryption_context))
        return getattr(sentinel, "{name}_{version}_encryption".format(name=self.name, version=self.version))

    def decryption_materials(self, encryption_context):
        self.provider_calls.append(("decryption_materials", encryption_context))
        return getattr(sentinel, "{name}_{version}_decryption".format(name=self.name, version=self.version))


class MockProviderStore(ProviderStore):
    def __init__(self):
        self.provider_calls = []
        self._providers = defaultdict(dict)

    def get_or_create_provider(self, material_name, version):
        self.provider_calls.append(("get_or_create_provider", material_name, version))
        try:
            return self._providers[material_name][version]
        except KeyError:
            self._providers[material_name][version] = SentinelCryptoMaterialsProvider(material_name, version)
        return self._providers[material_name][version]

    def max_version(self, material_name):
        self.provider_calls.append(("max_version", material_name))
        try:
            return sorted(self._providers[material_name].keys())[-1]
        except IndexError:
            raise NoKnownVersionError('No known version for name: "{}"'.format(material_name))

    def version_from_material_description(self, material_description):
        self.provider_calls.append(("version_from_material_description", material_description))
        return material_description


def test_failed_lock_acquisition():
    store = MagicMock(__class__=ProviderStore)
    provider = MostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)
    provider._version = 9
    provider._cache.put(provider._version, sentinel.nine)

    with provider._lock:
        test = provider._get_most_recent_version(allow_local=True)

    assert test is sentinel.nine
    assert not store.mock_calls


def test_encryption_materials_cache_use():
    store = MockProviderStore()
    name = "material"
    provider = MostRecentProvider(provider_store=store, material_name=name, version_ttl=10.0)

    test1 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test1 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    expected_calls = [
        ("max_version", name),
        ("get_or_create_provider", name, 0),
        ("version_from_material_description", 0),
    ]

    assert store.provider_calls == expected_calls

    test2 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test2 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    assert store.provider_calls == expected_calls


def test_decryption_materials_cache_use():
    store = MockProviderStore()
    name = "material"
    provider = MostRecentProvider(provider_store=store, material_name=name, version_ttl=10.0)

    context = MagicMock(material_description=0)

    test1 = provider.decryption_materials(context)
    assert test1 is sentinel.material_0_decryption

    assert len(provider._cache._cache) == 1

    expected_calls = [("version_from_material_description", 0), ("get_or_create_provider", name, 0)]

    assert store.provider_calls == expected_calls

    test2 = provider.decryption_materials(context)
    assert test2 is sentinel.material_0_decryption

    assert len(provider._cache._cache) == 1

    expected_calls.append(("version_from_material_description", 0))

    assert store.provider_calls == expected_calls
