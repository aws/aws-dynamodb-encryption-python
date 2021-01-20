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
import time
from collections import defaultdict

import pytest
from mock import MagicMock, sentinel

from dynamodb_encryption_sdk.exceptions import NoKnownVersionError
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.material_providers.most_recent import CachingMostRecentProvider, TtlActions
from dynamodb_encryption_sdk.material_providers.store import ProviderStore

from ..functional_test_utils import example_table  # noqa=F401 pylint: disable=unused-import
from ..functional_test_utils import mock_ddb_service  # noqa=F401 pylint: disable=unused-import
from ..functional_test_utils import mock_metastore  # noqa=F401 pylint: disable=unused-import
from ..functional_test_utils import TEST_TABLE_NAME, check_metastore_cache_use_encrypt

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


def test_constructor():
    """Tests that when the cache is expired on encrypt, we evict the entry from the cache."""
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=1.0, cache_size=42)

    assert provider._provider_store == store
    assert provider._material_name == name
    assert provider._version_ttl == 1.0
    assert provider._cache.capacity == 42


def test_ttl_action_first_encrypt():
    """Test that when _last_updated has never been set, ttl_action returns TtlActions.EXPIRED."""
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(0, "encrypt")
    assert ttl_action is TtlActions.EXPIRED


def test_ttl_action_first_encrypt_previous_decrypt():
    """Test that on the first call to encrypt, ttl_action returns TtlActions.EXPIRED."""
    version = 0
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)
    provider._cache.put(version, "bar")

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(version, "encrypt")
    assert ttl_action is TtlActions.EXPIRED


def test_ttl_action_not_in_cache():
    """Test that when a version is not in the cache, ttl_action returns TtlActions.EXPIRED."""
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(0, "decrypt")
    assert ttl_action is TtlActions.EXPIRED


def test_ttl_action_live():
    """Test that when a version is within the ttl, ttl_action returns TtlActions.LIVE."""
    version = 0
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)
    provider._cache.put(version, (time.time(), "value"))

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(version, "decrypt")
    assert ttl_action is TtlActions.LIVE


def test_ttl_action_grace_period():
    """Test that when a version is in the grace period, ttl_action returns TtlActions.GRACE_PERIOD."""
    version = 0
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=0.0)
    provider._grace_period = 10.0
    provider._cache.put(version, (time.time(), "value"))

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(version, "decrypt")
    assert ttl_action is TtlActions.GRACE_PERIOD


def test_ttl_action_expired():
    """Test that when a version is expired and not in the grace period, ttl_action returns TtlActions.EXPIRED."""
    version = 0
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=0.0)
    provider._grace_period = 0.0
    provider._cache.put(version, (time.time(), "value"))

    assert provider._last_updated is None

    ttl_action = provider._ttl_action(version, "decrypt")
    assert ttl_action is TtlActions.EXPIRED


def test_get_provider_with_grace_period_expired():
    """Test for _get_provider_with_grace_period when entry is expired.

    When the entry is expired, we should check the cache before going to the provider store.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (sentinel.timestamp, sentinel.provider)

    test1 = provider._get_provider_with_grace_period(sentinel.version, TtlActions.EXPIRED)
    assert test1 == sentinel.provider

    expected_calls = []
    assert store.provider_calls == expected_calls


def test_get_provider_with_grace_period_grace_period_lock_acquired():
    """Test for _get_provider_with_grace_period when entry is in grace period.

    When the entry is in grace_period and we acquire the lock, we should go to the provider store
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)

    provider._get_provider_with_grace_period(sentinel.version, TtlActions.GRACE_PERIOD)
    assert len(provider._cache._cache) == 1

    expected_calls = [("get_or_create_provider", name, sentinel.version)]
    assert store.provider_calls == expected_calls


def test_get_provider_with_grace_period_grace_period_lock_not_acquired():
    """Test for _get_provider_with_grace_period when entry is in grace period.

    When the entry is in grace_period and we do not acquire the lock, we should not go to the provider store
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (sentinel.timestamp, sentinel.provider)
    provider._lock = MagicMock()
    provider._lock.acquire.return_value = False

    test = provider._get_provider_with_grace_period(sentinel.version, TtlActions.GRACE_PERIOD)
    assert test == sentinel.provider

    expected_calls = []
    assert store.provider_calls == expected_calls


def test_get_most_recent_version_expired():
    """Test for _get_most_recent_version when entry is expired.

    When the entry is expired, we should check the cache before going to the provider store.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (sentinel.timestamp, sentinel.provider)

    test1 = provider._get_most_recent_version(TtlActions.EXPIRED)
    assert test1 == sentinel.provider

    expected_calls = []
    assert store.provider_calls == expected_calls


def test_get_most_recent_version_grace_period_lock_acquired():
    """Test for _get_most_recent_version when entry is in grace period.

    When the entry is in grace_period and we acquire the lock, we should go to the provider store
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)

    provider._get_most_recent_version(TtlActions.GRACE_PERIOD)
    assert len(provider._cache._cache) == 1

    expected_calls = [
        ("max_version", name),
        ("get_or_create_provider", name, 0),
        ("version_from_material_description", 0),
    ]
    assert store.provider_calls == expected_calls


def test_get_most_recent_version_grace_period_lock_not_acquired():
    """Test for _get_most_recent_version when entry is in grace period.

    When the entry is in grace_period and we do not acquire the lock, we should not go to the provider store
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (sentinel.timestamp, sentinel.provider)
    provider._lock = MagicMock()
    provider._lock.acquire.return_value = False

    test = provider._get_most_recent_version(TtlActions.GRACE_PERIOD)
    assert test == sentinel.provider

    expected_calls = []
    assert store.provider_calls == expected_calls


def test_failed_lock_acquisition():
    store = MagicMock(__class__=ProviderStore)
    provider = CachingMostRecentProvider(provider_store=store, material_name="my material", version_ttl=10.0)
    provider._version = 9
    provider._cache.put(provider._version, (time.time(), sentinel.nine))

    with provider._lock:
        test = provider._get_most_recent_version(ttl_action=TtlActions.GRACE_PERIOD)

    assert test is sentinel.nine
    assert not store.mock_calls


def test_encryption_materials_cache_use():
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=10.0)

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


def test_encryption_materials_cache_expired():
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)

    test1 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test1 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    # On the first call, we expect calls to each of the provider's APIs
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

    # On the second call, we don't call get_or_create because max_version matches the version in the cache.
    expected_calls.append(("max_version", name))
    expected_calls.append(("version_from_material_description", 0))

    assert store.provider_calls == expected_calls


def test_encryption_materials_cache_expired_cache_removed():
    """Tests that when the cache is expired on encrypt, we evict the entry from the cache."""
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (0.0, MagicMock())

    provider.encryption_materials(sentinel.encryption_context_1)
    provider._cache.evict.assert_called_once()


def test_decryption_materials_cache_expired_cache_removed():
    """Tests that when the cache is expired on decrypt, we evict the entry from the cache."""
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._cache = MagicMock()
    provider._cache.get.return_value = (0.0, MagicMock())

    provider.encryption_materials(sentinel.encryption_context_1)
    provider._cache.evict.assert_called_once()


def test_encryption_materials_cache_in_grace_period_acquire_lock():
    """Test encryption grace period behavior.

    When the TTL is GRACE_PERIOD and we successfully acquire the lock for retrieving new materials,
    we call to the provider store for new materials.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._grace_period = 10.0

    test1 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test1 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    # On the first call, we expect calls to each of the provider's APIs
    expected_calls = [
        ("max_version", name),
        ("get_or_create_provider", name, 0),
        ("version_from_material_description", 0),
    ]

    assert store.provider_calls == expected_calls

    provider._lock = MagicMock()
    provider._lock.acquire.return_value = True

    test2 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test2 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    # On the second call, we acquired the lock so we should have tried to retrieve new materials (note no extra call
    # to get_or_create_provider, because the version has not changed)
    expected_calls.append(("max_version", name))
    expected_calls.append(("version_from_material_description", 0))
    assert store.provider_calls == expected_calls


def test_encryption_materials_cache_in_grace_period_fail_to_acquire_lock():
    """Test encryption grace period behavior.

    When the TTL is GRACE_PERIOD and we fail to acquire the lock for retrieving new materials,
    we use the materials from the cache.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._grace_period = 10.0

    test1 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test1 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    # On the first call, we expect calls to each of the provider's APIs
    expected_calls = [
        ("max_version", name),
        ("get_or_create_provider", name, 0),
        ("version_from_material_description", 0),
    ]

    assert store.provider_calls == expected_calls

    # Now that the cache is populated, pretend the lock cannot be acquired; grace_period should allow the cached value
    provider._lock = MagicMock()
    provider._lock.acquire.return_value = False

    test2 = provider.encryption_materials(sentinel.encryption_context_1)
    assert test2 is sentinel.material_0_encryption

    assert provider._version == 0
    assert len(provider._cache._cache) == 1

    # On the second call, we expect no additional calls because we are in our grace period.
    assert store.provider_calls == expected_calls


def test_decryption_materials_cache_use():
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=10.0)

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


def test_caching_provider_decryption_materials_cache_expired():
    """Test decryption expiration behavior for CachingMostRecentProvider.

    When using a CachingMostRecentProvider and the cache is expired on decryption, we retrieve materials
    from the provider store again.
    Note that this test only runs for CachingMostRecentProvider, as MostRecentProvider does not use TTL on decryption.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)

    context = MagicMock(material_description=0)

    test1 = provider.decryption_materials(context)
    assert test1 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    expected_calls = [("version_from_material_description", 0), ("get_or_create_provider", name, 0)]

    assert store.provider_calls == expected_calls

    test2 = provider.decryption_materials(context)
    assert test2 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    # With the cache expired, we should see another call to get_or_create_provider
    expected_calls.append(("version_from_material_description", 0))
    expected_calls.append(("get_or_create_provider", name, 0))

    assert store.provider_calls == expected_calls


def test_caching_provider_decryption_materials_cache_in_grace_period_acquire_lock():
    """Test decryption grace period behavior for CachingMostRecentProvider.

    When using a CachingMostRecentProvider and the cache is in grace period on decryption and we
    successfully acquire the lock, we retrieve new materials.
    Note that this test only runs for CachingMostRecentProvider, as MostRecentProvider does not use TTL on decryption.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._grace_period = 10.0

    context = MagicMock(material_description=0)

    test1 = provider.decryption_materials(context)
    assert test1 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    expected_calls = [("version_from_material_description", 0), ("get_or_create_provider", name, 0)]

    assert store.provider_calls == expected_calls

    provider._lock = MagicMock()
    provider._lock.acquire.return_value = True

    test2 = provider.decryption_materials(context)
    assert test2 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    # Since we successfully acquired the lock we should have made a new call to the provider store
    expected_calls.append(("version_from_material_description", 0))
    expected_calls.append(("get_or_create_provider", name, 0))

    assert store.provider_calls == expected_calls


def test_caching_provider_decryption_materials_cache_in_grace_period_fail_to_acquire_lock():
    """Test decryption grace period behavior for CachingMostRecentProvider.

    When using a CachingMostRecentProvider and the cache is in grace period on decryption and we fail to
    acquire the lock, we use materials from the cache.
    Note that this test only runs for CachingMostRecentProvider, as MostRecentProvider does not use TTL on decryption.
    """
    store = MockProviderStore()
    name = "material"
    provider = CachingMostRecentProvider(provider_store=store, material_name=name, version_ttl=0.0)
    provider._grace_period = 10.0

    context = MagicMock(material_description=0)

    test1 = provider.decryption_materials(context)
    assert test1 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    expected_calls = [("version_from_material_description", 0), ("get_or_create_provider", name, 0)]

    assert store.provider_calls == expected_calls

    # Now that the cache is populated, pretend the lock cannot be acquired; grace_period should allow the cached value
    provider._lock = MagicMock()
    provider._lock.acquire.return_value = False

    test2 = provider.decryption_materials(context)
    assert test2 is sentinel.material_0_decryption
    assert len(provider._cache._cache) == 1

    # Since we used the cache value, we should not see another call to get_or_create_provider
    expected_calls.append(("version_from_material_description", 0))

    assert store.provider_calls == expected_calls


def test_cache_use_encrypt(mock_metastore, example_table, caplog):
    check_metastore_cache_use_encrypt(mock_metastore, TEST_TABLE_NAME, caplog)
