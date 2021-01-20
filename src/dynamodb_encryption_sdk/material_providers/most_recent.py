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
"""Cryptographic materials provider that uses a provider store to obtain cryptographic materials."""
import logging
import time
from collections import OrderedDict
from enum import Enum
from threading import Lock, RLock

import attr
import six

from dynamodb_encryption_sdk.exceptions import InvalidVersionError, NoKnownVersionError
from dynamodb_encryption_sdk.identifiers import LOGGER_NAME
from dynamodb_encryption_sdk.materials import CryptographicMaterials  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.structures import EncryptionContext  # noqa pylint: disable=unused-import

from . import CryptographicMaterialsProvider
from .store import ProviderStore

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


__all__ = (
    "CachingMostRecentProvider",
)
_LOGGER = logging.getLogger(LOGGER_NAME)
#: Grace period during which we will return the latest local materials. This allows multiple
#: threads to be using this same provider without risking lock contention or many threads
#: all attempting to create new versions simultaneously.
_GRACE_PERIOD = 0.5
_ENCRYPT_ACTION = "encrypt"
_DECRYPT_ACTION = "decrypt"


class TtlActions(Enum):
    """Actions that can be taken based on the version TTl state."""

    EXPIRED = 0
    GRACE_PERIOD = 1
    LIVE = 2


def _min_capacity_validator(instance, attribute, value):
    # pylint: disable=unused-argument
    """Attrs validator to require that value is at least 1."""
    if value < 1:
        raise ValueError("Cache capacity must be at least 1")


@attr.s(init=False)
class BasicCache(object):
    """Most basic LRU cache."""

    capacity = attr.ib(validator=(attr.validators.instance_of(int), _min_capacity_validator))

    def __init__(self, capacity):  # noqa=D107
        # type: (int) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.capacity = capacity
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type; () -> None
        """Initialize the internal cache."""
        self._cache_lock = RLock()  # attrs confuses pylint: disable=attribute-defined-outside-init
        self.clear()

    def _prune(self):
        # type: () -> None
        """Prunes internal cache until internal cache is within the defined limit."""
        with self._cache_lock:
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)

    def put(self, name, value):
        # type: (Any, Any) -> None
        """Add a value to the cache.

        :param name: Hashable object to identify the value in the cache
        :param value: Value to add to cache
        """
        with self._cache_lock:
            self._cache[name] = value
            self._prune()

    def get(self, name):
        # type: (Any) -> Any
        """Get a value from the cache.

        :param name: Object to identify the value in the cache
        :returns: Value from cache
        """
        with self._cache_lock:
            value = self._cache.pop(name)
            # Re-insert the item to bump it to the front of the LRU cache
            self.put(name, value)
            return value

    def clear(self):
        # type: () -> None
        """Clear the cache."""
        _LOGGER.debug("Clearing cache")
        with self._cache_lock:
            self._cache = OrderedDict()  # type: OrderedDict[Any, Any] # pylint: disable=attribute-defined-outside-init

    def evict(self, name):
        # type: (Any) -> None
        """Evict a single entry from the cache."""
        with self._cache_lock:
            try:
                del self._cache[name]
            except KeyError:
                # If the key wasn't in the cache, do nothing
                pass


@attr.s(init=False)
@attr.s(init=False)
class CachingMostRecentProvider(CryptographicMaterialsProvider):
    # pylint: disable=too-many-instance-attributes
    """Cryptographic materials provider that uses a provider store to obtain cryptography
    materials. Materials obtained from the store are cached for a user-defined amount of time,
    then removed from the cache and re-retrieved from the store.

    When encrypting, the most recent provider that the provider store knows about will always
    be used.

    :param ProviderStore provider_store: Provider store to use
    :param str material_name: Name of materials for which to ask the provider store
    :param float version_ttl: Max time in seconds to go until checking with provider store
        for a more recent version
    :param int cache_size: The maximum number of entries that the cache can hold
    """

    _provider_store = attr.ib(validator=attr.validators.instance_of(ProviderStore))
    _material_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _version_ttl = attr.ib(validator=attr.validators.instance_of(float))
    _cache_size = attr.ib(validator=attr.validators.instance_of(int))

    def __init__(self, provider_store, material_name, version_ttl, cache_size=1000):  # noqa=D107
        # type: (ProviderStore, Text, float, int) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._provider_store = provider_store
        self._material_name = material_name
        self._version_ttl = version_ttl
        self._grace_period = _GRACE_PERIOD
        self._cache_size = cache_size
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type: () -> None
        """Initialize the cache."""
        self._version = None  # type: int # pylint: disable=attribute-defined-outside-init
        self._last_updated = None  # type: float # pylint: disable=attribute-defined-outside-init
        self._lock = Lock()  # pylint: disable=attribute-defined-outside-init
        self._cache = BasicCache(self._cache_size)  # pylint: disable=attribute-defined-outside-init
        self.refresh()

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return decryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :raises AttributeError: if no decryption materials are available
        """
        provider = None

        version = self._provider_store.version_from_material_description(encryption_context.material_description)

        ttl_action = self._ttl_action(version, _DECRYPT_ACTION)

        if ttl_action is TtlActions.EXPIRED:
            self._cache.evict(self._version)

        _LOGGER.debug('TTL Action "%s" when getting decryption materials', ttl_action.name)
        if ttl_action is TtlActions.LIVE:
            try:
                _LOGGER.debug("Looking in cache for encryption materials provider version %d", version)
                _, provider = self._cache.get(version)
            except KeyError:
                _LOGGER.debug("Decryption materials provider not found in cache")

        if provider is None:
            try:
                provider = self._get_provider_with_grace_period(version, ttl_action)
            except InvalidVersionError:
                _LOGGER.exception("Unable to get decryption materials from provider store.")
                raise AttributeError("No decryption materials available")

        return provider.decryption_materials(encryption_context)

    def _ttl_action(self, version, action):
        # type: (str) -> TtlActions
        """Determine the correct action to take based on the local resources and TTL.

        :param action: The action being taken (encrypt or decrypt)

        :returns: decision
        :rtype: TtlActions
        """
        try:
            if action == _ENCRYPT_ACTION:
                # On encrypt, always check the class-level variable indicating when we last checked for updates.
                # The cache timestamps will be updated by calls to decrypt, so we don't want frequent decrypts to
                # prevent us from re-checking for a newer encryption version
                if self._last_updated is None:
                    return TtlActions.EXPIRED
                timestamp = self._last_updated
            else:
                timestamp, _ = self._cache.get(version)
            time_since_updated = time.time() - timestamp

            if time_since_updated < self._version_ttl:
                return TtlActions.LIVE

            if time_since_updated < self._version_ttl + self._grace_period:
                return TtlActions.GRACE_PERIOD

            _LOGGER.debug("TTL Expired because known version has expired")
            return TtlActions.EXPIRED
        except KeyError:
            _LOGGER.debug("TTL Expired because the requested version doesn't exist in the cache")
            return TtlActions.EXPIRED

    def _get_max_version(self):
        # type: () -> int
        """Ask the provider store for the most recent version of this material.

        :returns: Latest version in the provider store (0 if not found)
        :rtype: int
        """
        try:
            return self._provider_store.max_version(self._material_name)
        except NoKnownVersionError:
            return 0

    def _get_provider(self, version):
        # type: (int) -> CryptographicMaterialsProvider
        """Ask the provider for a specific version of this material.

        :param int version: Version to request
        :returns: Cryptographic materials provider for the requested version
        :rtype: CryptographicMaterialsProvider
        :raises AttributeError: if provider could not locate version
        """
        try:
            return self._provider_store.get_or_create_provider(self._material_name, version)
        except InvalidVersionError:
            _LOGGER.exception("Unable to get encryption materials from provider store.")
            raise AttributeError("No encryption materials available")

    def _get_provider_with_grace_period(self, version, ttl_action):
        # type: (int, bool) -> CryptographicMaterialsProvider
        """Ask the provider to retrieve a specific version of this material, falling back to the cache if
        another caller currently holds the lock for retrieval.

        :param int version: Version to request
        :param TtlActions ttl_action: The ttl action to take for this version
        :returns: Cryptographic materials provider for the requested version
        :rtype: CryptographicMaterialsProvider
        :raises AttributeError: if provider could not locate version
        """
        blocking_wait = bool(ttl_action is TtlActions.EXPIRED)
        acquired = self._lock.acquire(blocking_wait)
        if not acquired:
            # We failed to acquire the lock.
            # If blocking, we will never reach this point.
            # If not blocking, we want whatever the latest local version is.
            _LOGGER.debug("Failed to acquire lock. Returning the last cached version.")
            _, provider = self._cache.get(version)
            return provider

        try:
            # If the entry was expired then we blocked waiting for the lock, so it's possible some other thread already
            # queried the provider store and re-populated the cache. If so, we don't want to re-query the provider
            # store, so check if the entry is back in the cache first
            if ttl_action is TtlActions.EXPIRED:
                try:
                    _, provider = self._cache.get(version)
                    return provider
                except KeyError:
                    pass
            provider = self._provider_store.provider(self._material_name, version)
            self._cache.put(version, (time.time(), provider))
            return provider
        finally:
            self._lock.release()

    def _get_most_recent_version(self, ttl_action):
        # type: (bool) -> CryptographicMaterialsProvider
        """Get the most recent version of the provider.

        If allowing local and we cannot obtain the lock, just return the most recent local
        version. Otherwise, wait for the lock and ask the provider store for the most recent
        version of the provider.

        :param TtlActions ttl_action: The ttl action to take for this version
        :returns: version and corresponding cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        """
        blocking_wait = bool(ttl_action is TtlActions.EXPIRED)
        acquired = self._lock.acquire(blocking_wait)

        if not acquired:
            # We failed to acquire the lock.
            # If blocking, we will never reach this point.
            # If not blocking, we want whatever the latest local version is.
            _LOGGER.debug("Failed to acquire lock. Returning the last cached version.")
            version = self._version
            _, provider = self._cache.get(version)
            return provider

        try:
            # If the entry was expired then we blocked waiting for the lock, so it's possible some other thread already
            # queried the provider store and re-populated the cache. If so, we don't want to re-query the provider
            # store, so check if the entry is back in the cache first
            if ttl_action is TtlActions.EXPIRED:
                try:
                    _, provider = self._cache.get(self._version)
                    return provider
                except KeyError:
                    pass

            max_version = self._get_max_version()
            try:
                _, provider = self._cache.get(max_version)
            except KeyError:
                provider = self._get_provider(max_version)
            received_version = self._provider_store.version_from_material_description(
                provider._material_description  # pylint: disable=protected-access
            )

            _LOGGER.debug("Caching materials provider version %d", received_version)
            self._version = received_version  # pylint: disable=attribute-defined-outside-init
            self._last_updated = time.time()  # pylint: disable=attribute-defined-outside-init
            self._cache.put(received_version, (self._last_updated, provider))
        finally:
            self._lock.release()

        _LOGGER.debug("New latest version is %d", self._version)

        return provider

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return encryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :raises AttributeError: if no encryption materials are available
        """
        ttl_action = self._ttl_action(self._version, _ENCRYPT_ACTION)

        _LOGGER.debug('TTL Action "%s" when getting encryption materials', ttl_action.name)

        provider = None

        if ttl_action is TtlActions.EXPIRED:
            self._cache.evict(self._version)

        if ttl_action is TtlActions.LIVE:
            try:
                _LOGGER.debug("Looking in cache for encryption materials provider version %d", self._version)
                _, provider = self._cache.get(self._version)
            except KeyError:
                _LOGGER.debug("Encryption materials provider not found in cache")
                ttl_action = TtlActions.EXPIRED

        if provider is None:
            _LOGGER.debug("Getting most recent materials provider version")
            provider = self._get_most_recent_version(ttl_action)

        return provider.encryption_materials(encryption_context)

    def refresh(self):
        # type: () -> None
        """Clear all local caches for this provider."""
        _LOGGER.debug("Refreshing CachingMostRecentProvider instance.")
        with self._lock:
            self._cache.clear()
            self._version = None  # type: int # pylint: disable=attribute-defined-outside-init
            self._last_updated = None  # type: float # pylint: disable=attribute-defined-outside-init
