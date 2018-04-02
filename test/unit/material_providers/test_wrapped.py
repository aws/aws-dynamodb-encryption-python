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
"""Unit tests for ``dynamodb_encryption_sdk.material_providers.wrapped``."""
from mock import MagicMock
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from dynamodb_encryption_sdk.delegated_keys import DelegatedKey
from dynamodb_encryption_sdk.exceptions import UnwrappingError, WrappingError
import dynamodb_encryption_sdk.material_providers.wrapped
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import EncryptionContext

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize('method, error_type, message', (
    ('decryption_materials', UnwrappingError, 'Decryption materials cannot be provided: no unwrapping key'),
    ('encryption_materials', WrappingError, 'Encryption materials cannot be provided: no wrapping key')
))
def test_no_materials(method, error_type, message):
    empty_cmp = WrappedCryptographicMaterialsProvider(
        signing_key=MagicMock(__class__=DelegatedKey)
    )

    with pytest.raises(error_type) as excinfo:
        getattr(empty_cmp, method)(EncryptionContext())

    excinfo.match(message)


@pytest.mark.parametrize('invalid_kwargs', (
    dict(signing_key=None),
    dict(wrapping_key='not a delegated key'),
    dict(unwrapping_key='not a delegated key')
))
def test_attrs_fail(invalid_kwargs):
    kwargs = dict(signing_key=MagicMock(__class__=DelegatedKey))
    kwargs.update(invalid_kwargs)

    with pytest.raises(TypeError):
        WrappedCryptographicMaterialsProvider(**kwargs)


@pytest.mark.parametrize('method', ('decryption_materials', 'encryption_materials'))
def test_valid_materials(mocker, method):
    mocker.patch.object(WrappedCryptographicMaterialsProvider, '_build_materials')

    cmp = WrappedCryptographicMaterialsProvider(
        signing_key=MagicMock(__class__=DelegatedKey),
        wrapping_key=MagicMock(__class__=DelegatedKey),
        unwrapping_key=MagicMock(__class__=DelegatedKey)
    )

    context = EncryptionContext()
    test = getattr(cmp, method)(context)

    WrappedCryptographicMaterialsProvider._build_materials.assert_called_once_with(context)
    assert test is WrappedCryptographicMaterialsProvider._build_materials.return_value


def test_build_materials(mocker):
    mocker.patch.object(dynamodb_encryption_sdk.material_providers.wrapped, 'WrappedCryptographicMaterials')

    cmp = WrappedCryptographicMaterialsProvider(
        signing_key=MagicMock(__class__=DelegatedKey),
        wrapping_key=MagicMock(__class__=DelegatedKey),
        unwrapping_key=MagicMock(__class__=DelegatedKey)
    )

    material_description = {'some': 'data'}
    context = EncryptionContext(material_description=material_description)
    test = cmp._build_materials(context)

    dynamodb_encryption_sdk.material_providers.wrapped.WrappedCryptographicMaterials.assert_called_once_with(
        wrapping_key=cmp._wrapping_key,
        unwrapping_key=cmp._unwrapping_key,
        signing_key=cmp._signing_key,
        material_description=material_description
    )
    assert test is dynamodb_encryption_sdk.material_providers.wrapped.WrappedCryptographicMaterials.return_value
