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
"""Cryptographic materials provider stores."""
import abc

import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Text, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import NoKnownVersionError
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider  # noqa pylint: disable=unused-import

__all__ = ('ProviderStore',)


@six.add_metaclass(abc.ABCMeta)
class ProviderStore(object):
    """Provide a standard way to retrieve and/or create cryptographic materials providers."""

    @abc.abstractmethod
    def get_or_create_provider(self, material_name, version):
        # type: (Text, int) -> CryptographicMaterialsProvider
        """Obtain a cryptographic materials provider identified by a name and version.

        If the requested version does not exist, a new one might be created.

        :param str material_name: Material to locate
        :param int version: Version of material to locate (optional)
        :returns: cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        :raises InvalidVersionError: if the requested version is not available and cannot be created
        """

    @abc.abstractmethod
    def version_from_material_description(self, material_description):
        # (Dict[Text, Text]) -> int
        """Determine the version from the provided material description.

        :param dict material_description: Material description to use with this request
        :returns: version to use
        :rtype: int
        """

    def max_version(self, material_name):
        # (Text) -> int
        # pylint: disable=no-self-use
        """Find the maximum known version of the specified material.

        .. note::

            Child classes should usually override this method.

        :param str material_name: Material to locate
        :returns: Maximum known version
        :rtype: int
        :raises NoKnownVersionError: if no version can be found
        """
        raise NoKnownVersionError('No known version for name: "{}"'.format(material_name))

    def provider(self, material_name, version=None):
        # type: (Text, Optional[int]) -> CryptographicMaterialsProvider
        """Obtain a cryptographic materials provider identified by a name and version.

        If the version is not provided, the maximum version will be used.

        :param str material_name: Material to locate
        :param int version: Version of material to locate (optional)
        :returns: cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        :raises InvalidVersionError: if the requested version is not found
        """
        if version is None:
            try:
                version = self.max_version(material_name)
            except NoKnownVersionError:
                version = 0
        return self.get_or_create_provider(material_name, version)

    def new_provider(self, material_name):
        # type: (Text) -> CryptographicMaterialsProvider
        """Create a new provider with a version one greater than the current known maximum.

        :param str material_name: Material to locate
        :returns: cryptographic materials provider
        :rtype: CryptographicMaterialsProvider
        """
        version = self.max_version(material_name) + 1
        return self.get_or_create_provider(material_name, version)
