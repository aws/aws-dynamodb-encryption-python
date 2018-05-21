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
from collections import OrderedDict
from enum import Enum
import logging
from threading import Lock, RLock
import time

import attr
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Text  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import InvalidVersionError, NoKnownVersionError
from dynamodb_encryption_sdk.identifiers import LOGGER_NAME
from dynamodb_encryption_sdk.materials import CryptographicMaterials  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.structures import EncryptionContext  # noqa pylint: disable=unused-import
from . import CryptographicMaterialsProvider
from .store import ProviderStore

__all__ = ('MostRecentProvider',)
_LOGGER = logging.getLogger(LOGGER_NAME)
#: Grace period during which we will return the latest local materials. This allows multiple
#: threads to be using this same provider without risking lock contention or many threads
#: all attempting to create new versions simultaneously.
_GRACE_PERIOD = 0.5


class TtlActions(Enum):
    """Actions that can be taken based on the version TTl state."""

    EXPIRED = 0
    GRACE_PERIOD = 1
    LIVE = 2


def _min_capacity_validator(instance, attribute, value):
    # pylint: disable=unused-argument
    """Attrs validator to require that value is at least 1."""
    if value < 1:
        raise ValueError('Cache capacity must be at least 1')


@attr.s(init=False)
class BasicCache(object):
    """Most basic LRU cache."""

    capacity = attr.ib(validator=(
        attr.validators.instance_of(int),
        _min_capacity_validator
    ))

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
            self.put(name, value)  # bump to the from of the LRU
            return value

    def clear(self):
        # type: () -> None
        """Clear the cache."""
        with self._cache_lock:
            self._cache = OrderedDict()  # type: OrderedDict[Any, Any] # pylint: disable=attribute-defined-outside-init


@attr.s(init=False)
class MostRecentProvider(CryptographicMaterialsProvider):
    """Cryptographic materials provider that uses a provider store to obtain cryptography
    materials.

    When encrypting, the most recent provider that the provider store knows about will always
    be used.

    :param ProviderStore provider_store: Provider store to use
    :param str material_name: Name of materials for which to ask the provider store
    :param float version_ttl: Max time in seconds to go until checking with provider store
        for a more recent version
    """

    _provider_store = attr.ib(validator=attr.validators.instance_of(ProviderStore))
    _material_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    _version_ttl = attr.ib(validator=attr.validators.instance_of(float))

    def __init__(
            self,
            provider_store,  # type: ProviderStore
            material_name,  # type: Text
            version_ttl  # type: float
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._provider_store = provider_store
        self._material_name = material_name
        self._version_ttl = version_ttl
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type: () -> None
        """Initialize the cache."""
        self._version = None  # type: int # pylint: disable=attribute-defined-outside-init
        self._last_updated = None  # type: float # pylint: disable=attribute-defined-outside-init
        self._lock = Lock()  # pylint: disable=attribute-defined-outside-init
        self._cache = BasicCache(1000)  # pylint: disable=attribute-defined-outside-init
        self.refresh()

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return decryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :raises AttributeError: if no decryption materials are available
        """
        version = self._provider_store.version_from_material_description(encryption_context.material_description)
        try:
            provider = self._cache.get(version)
        except KeyError:
            try:
                provider = self._provider_store.provider(self._material_name, version)
            except InvalidVersionError:
                _LOGGER.exception('Unable to get decryption materials from provider store.')
                raise AttributeError('No decryption materials available')

        self._cache.put(version, provider)

        return provider.decryption_materials(encryption_context)

    def _ttl_action(self):
        # type: () -> TtlActions
        """Determine the correct action to take based on the local resources and TTL.

        :returns: decision
        :rtype: TtlActions
        """
        if self._version is None:
            return TtlActions.EXPIRED

        time_since_updated = time.time() - self._last_updated

        if time_since_updated < self._version_ttl:
            return TtlActions.LIVE

        elif time_since_updated < self._version_ttl + _GRACE_PERIOD:
            return TtlActions.GRACE_PERIOD

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
            _LOGGER.exception('Unable to get encryption materials from provider store.')
            raise AttributeError('No encryption materials available')

    def _get_most_recent_version(self, allow_local):
        # type: (bool) -> CryptographicMaterialsProvider
        """Get the most recent version of the provider.

        If allowing local and we cannot obtain the lock, just return the most recent local
        version. Otherwise, wait for the lock and ask the provider store for the most recent
        version of the provider.

        :param bool allow_local: Should we allow returning the local version if we cannot obtain the lock?
        :returns: version and corresponding cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        """
        acquired = self._lock.acquire(not allow_local)

        if not acquired:
            # We failed to acquire the lock.
            # If blocking, we will never reach this point.
            # If not blocking, we want whatever the latest local version is.
            version = self._version
            return self._cache.get(version)

        try:
            max_version = self._get_max_version()
            try:
                provider = self._cache.get(max_version)
            except KeyError:
                provider = self._get_provider(max_version)
            received_version = self._provider_store.version_from_material_description(provider._material_description)
            # TODO: ^ should we promote material description from hidden?

            self._version = received_version
            self._last_updated = time.time()
            self._cache.put(received_version, provider)
        finally:
            self._lock.release()

        return provider

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return encryption materials.

        :param EncryptionContext encryption_context: Encryption context for request
        :raises AttributeError: if no encryption materials are available
        """
        ttl_action = self._ttl_action()

        if ttl_action is TtlActions.LIVE:
            try:
                return self._cache.get(self._version)
            except KeyError:
                ttl_action = TtlActions.EXPIRED

        # Just get the latest local version if we cannot acquire the lock.
        # Otherwise, block until we can acquire the lock.
        allow_local = bool(ttl_action is TtlActions.GRACE_PERIOD)

        provider = self._get_most_recent_version(allow_local)

        return provider.encryption_materials(encryption_context)

    def refresh(self):
        # type: () -> None
        """Clear all local caches for this provider."""
        with self._lock:
            self._cache.clear()
            self._version = None  # type: int # pylint: disable=attribute-defined-outside-init
            self._last_updated = None  # type: float # pylint: disable=attribute-defined-outside-init
