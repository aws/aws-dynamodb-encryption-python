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
"""Resources for encrypting items."""
import copy

import attr

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

from dynamodb_encryption_sdk.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials import CryptographicMaterials  # noqa pylint: disable=unused-import
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext

__all__ = ('CryptoConfig',)


@attr.s(init=False)
class CryptoConfig(object):
    """Container for all configuration needed to encrypt or decrypt an item using the item
    encryptor functions in :py:mod:`dynamodb_encryption_sdk.encrypted.item`.

    :param CryptographicMaterialsProvider materials_provider: Cryptographic materials provider
        to use
    :param EncryptionContext encryption_context: Context data describing what is being encrypted
        or decrypted
    :param AttributeActions attribute_actions: Description of what action should be taken
        for each attribute
    """

    materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    encryption_context = attr.ib(validator=attr.validators.instance_of(EncryptionContext))
    attribute_actions = attr.ib(validator=attr.validators.instance_of(AttributeActions))

    def __init__(
            self,
            materials_provider,  # type: CryptographicMaterialsProvider
            encryption_context,  # type: EncryptionContext
            attribute_actions  # type: AttributeActions
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.materials_provider = materials_provider
        self.encryption_context = encryption_context
        self.attribute_actions = attribute_actions
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        # type: () -> None
        """Make sure that primary index attributes are not being encrypted."""
        if self.encryption_context.partition_key_name is not None:
            if self.attribute_actions.action(self.encryption_context.partition_key_name) is CryptoAction.ENCRYPT_AND_SIGN:  # noqa pylint: disable=line-too-long
                raise InvalidArgumentError('Cannot encrypt partition key')

        if self.encryption_context.sort_key_name is not None:
            if self.attribute_actions.action(self.encryption_context.sort_key_name) is CryptoAction.ENCRYPT_AND_SIGN:
                raise InvalidArgumentError('Cannot encrypt sort key')

    def decryption_materials(self):
        # type: () -> CryptographicMaterials
        """Load decryption materials from instance resources.

        :returns: Decryption materials
        :rtype: CryptographicMaterials
        """
        return self.materials_provider.decryption_materials(self.encryption_context)

    def encryption_materials(self):
        # type: () -> CryptographicMaterials
        """Load encryption materials from instance resources.

        :returns: Encryption materials
        :rtype: CryptographicMaterials
        """
        return self.materials_provider.encryption_materials(self.encryption_context)

    def copy(self):
        # type: () -> CryptoConfig
        """Return a copy of this instance with a copied instance of its encryption context.

        :returns: New :class:`CryptoConfig` identical to this one
        :rtype: CryptoConfig
        """
        return CryptoConfig(
            materials_provider=self.materials_provider,
            encryption_context=copy.copy(self.encryption_context),
            attribute_actions=self.attribute_actions
        )

    def with_item(self, item):
        """Return a copy of this instance with an encryption context that includes the provided item attributes.

        :param dict item: DynamoDB item in DynamnoDB JSON format
        :returns: New :class:`CryptoConfig` identical to this one
        :rtype: CryptoConfig
        """
        new_config = self.copy()
        new_config.encryption_context.attributes = item
        return new_config
