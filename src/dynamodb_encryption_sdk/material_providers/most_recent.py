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
"""Meta cryptographic provider store."""
from collections import OrderedDict
import logging
from threading import RLock
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


def _min_capacity_validator(instance, attribute, value):
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

    def __init__(self, capacity):
        # type: (int) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
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
        """Get a value from the cache."""
        with self._cache_lock:
            value = self._cache.pop(name)
            self.put(name, value)  # bump to the from of the LRU
            return value

    def clear(self):
        # type: () -> None
        """Clear the cache."""
        with self._cache_lock:
            self._cache = OrderedDict()  # type: OrderedDict[Any, Any]


@attr.s(init=False)
class MostRecentProvider(CryptographicMaterialsProvider):
    """Cryptographic materials provider that uses a provider store to obtain cryptography
    materials.

    When encrypting, the most recent provider that the provider store knows about will always
    be used.

    :param provider_store: Provider store to use
    :type provider_store: dynamodb_encryption_sdk.material_providers.store.ProviderStore
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
    ):
        # type: (...) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
        self._provider_store = provider_store
        self._material_name = material_name
        self._version_ttl = version_ttl
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type: () -> None
        """Initialize the cache."""
        self._lock = RLock()
        self._cache = BasicCache(1000)
        self.refresh()

    def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return decryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
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

    def _can_use_current(self):
        # type: () -> bool
        """Determine if we can use the current known max version without asking the provider store.

        :returns: decision
        :rtype: bool
        """
        if self._version is None:
            return False

        return time.time() - self._last_updated < self._version_ttl

    def _set_most_recent_version(self, version):
        # type: (int) -> None
        """Set the most recent version and update the last updated time.

        :param int version: Version to set
        """
        with self._lock:
            self._version = version
            self._last_updated = time.time()

    def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        """Return encryption materials.

        :param encryption_context: Encryption context for request
        :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
        :raises AttributeError: if no encryption materials are available
        """
        if self._can_use_current():
            return self._cache.get(self._version)

        try:
            version = self._provider_store.max_version(self._material_name)
        except NoKnownVersionError:
            version = 0

        try:
            provider = self._provider_store.get_or_create_provider(self._material_name, version)
        except InvalidVersionError:
            _LOGGER.exception('Unable to get encryption materials from provider store.')
            raise AttributeError('No encryption materials available')
        actual_version = self._provider_store.version_from_material_description(provider._material_description)
        # TODO: ^ should we promote material description from hidden?

        self._cache.put(actual_version, provider)
        self._set_most_recent_version(actual_version)

        return provider.encryption_materials(encryption_context)

    def refresh(self):
        # type: () -> None
        """Clear all local caches for this provider."""
        with self._lock:
            self._cache.clear()
            self._version = None  # type: int
            self._last_updated = None  # type: CryptographicMaterialsProvider
