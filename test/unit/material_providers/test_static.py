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
"""Unit tests for ``dynamodb_encryption_sdk.material_providers.static``."""
from mock import MagicMock
import pytest

from dynamodb_encryption_sdk.material_providers.static import StaticCryptographicMaterialsProvider
from dynamodb_encryption_sdk.materials import DecryptionMaterials, EncryptionMaterials
from dynamodb_encryption_sdk.structures import EncryptionContext

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize('method, message', (
    ('decryption_materials', 'No decryption materials available'),
    ('encryption_materials', 'No encryption materials available')
))
def test_no_materials(method, message):
    empty_cmp = StaticCryptographicMaterialsProvider()

    with pytest.raises(AttributeError) as excinfo:
        getattr(empty_cmp, method)(EncryptionContext())

    excinfo.match(message)


@pytest.mark.parametrize('invalid_kwargs', (
    dict(decryption_materials='not decryption materails'),
    dict(encryption_materials='not encryption materails')
))
def test_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        StaticCryptographicMaterialsProvider(**invalid_kwargs)


@pytest.mark.parametrize('materials, method', (
    (MagicMock(__class__=DecryptionMaterials), 'decryption_materials'),
    (MagicMock(__class__=EncryptionMaterials), 'encryption_materials')
))
def test_valid_materials(materials, method):
    kwargs = {method: materials}
    static_cmp = StaticCryptographicMaterialsProvider(**kwargs)

    assert getattr(static_cmp, method)(EncryptionContext()) is materials
