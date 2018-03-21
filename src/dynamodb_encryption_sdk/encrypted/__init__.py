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
import attr
import copy

from dynamodb_encryption_sdk.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk.identifiers import ItemAction
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials import DecryptionMaterials, EncryptionMaterials
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext

__all__ = ('CryptoConfig',)


@attr.s
class CryptoConfig(object):
    """Container for all configuration needed to encrypt or decrypt an item.

    :param materials_provider: Cryptographic materials provider to use
    :type materials_provider: dynamodb_encryption_sdk.material_providers.CryptographicMaterialsProvider
    :param encryption_context: Context data describing what is being encrypted or decrypted.
    :type encryption_context: dynamodb_encryption_sdk.structures.EncryptionContext
    :param attribute_actions: Description of what action should be taken for each attribute
    :type attribute_actions: dynamodb_encryption_sdk.structures.AttributeActions
    """
    materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    encryption_context = attr.ib(validator=attr.validators.instance_of(EncryptionContext))
    attribute_actions = attr.ib(validator=attr.validators.instance_of(AttributeActions))

    def __attrs_post_init__(self):
        """Make sure that primary index attributes are not being encrypted."""
        if self.encryption_context.partition_key_name is not None:
            if self.attribute_actions.action(self.encryption_context.partition_key_name) is ItemAction.ENCRYPT_AND_SIGN:
                raise InvalidArgumentError('Cannot encrypt partition key')

        if self.encryption_context.sort_key_name is not None:
            if self.attribute_actions.action(self.encryption_context.sort_key_name) is ItemAction.ENCRYPT_AND_SIGN:
                raise InvalidArgumentError('Cannot encrypt sort key')

    def decryption_materials(self):
        """Load decryption materials from instance resources.

        :returns: Decryption materials
        :rtype: dynamodb_encryption_sdk.materials.DecryptionMaterials
        """
        return self.materials_provider.decryption_materials(self.encryption_context)

    def encryption_materials(self):
        """Load encryption materials from instance resources.

        :returns: Encryption materials
        :rtype: dynamodb_encryption_sdk.materials.EncryptionMaterials
        """
        return self.materials_provider.encryption_materials(self.encryption_context)

    def copy(self):
        """Return a copy of this instance with a copied instance of its encryption context.

        :returns: New CryptoConfig identical to this one
        :rtype: CryptoConfig
        """
        return CryptoConfig(
            materials_provider=self.materials_provider,
            encryption_context=copy.copy(self.encryption_context),
            attribute_actions=self.attribute_actions
        )


def validate_get_arguments(kwargs):
    """Verify that attribute filtering parameters are not found in the request.

    :raises InvalidArgumentError: if banned parameters are found
    """
    for arg in ('AttributesToGet', 'ProjectionExpression'):
        if arg in kwargs:
            raise InvalidArgumentError('"{}" is not supported for this operation'.format(arg))

    if kwargs.get('Select', None) in ('SPECIFIC_ATTRIBUTES', 'ALL_PROJECTED_ATTRIBUTES', 'SPECIFIC_ATTRIBUTES'):
        raise InvalidArgumentError('Scan "Select" value of "{}" is not supported'.format(kwargs['Select']))
