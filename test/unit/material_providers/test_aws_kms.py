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
"""Unit tests for ``dynamodb_encryption_sdk.material_providers.aws_kms``."""
import base64
from mock import MagicMock, sentinel

import boto3
import botocore
from moto import mock_kms
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.exceptions import UnknownRegionError, UnwrappingError, WrappingError
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType
import dynamodb_encryption_sdk.material_providers.aws_kms
from dynamodb_encryption_sdk.material_providers.aws_kms import (
    _DEFAULT_CONTENT_ENCRYPTION_ALGORITHM, _DEFAULT_SIGNING_ALGORITHM,
    AwsKmsCryptographicMaterialsProvider, KeyInfo
)
from dynamodb_encryption_sdk.structures import EncryptionContext

pytestmark = [pytest.mark.unit, pytest.mark.local]

_VALID_KEY_INFO_KWARGS = dict(
    description='some string',
    algorithm='algorithm name',
    length=1234
)
_REGION = 'fake-region'
_KEY_ID = 'arn:aws:kms:{}:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'.format(_REGION)
_DERIVED_KEYS = {
    'initial_material': b'\xafx2"\xb5\xd5`\xc6\x8d\xaa\xfe\xc10E3x?D\x18\x93$<\x161\xcb\x99\xef\xc0Z\x1a\x1b]',
    'encrypted_initial_material': (
        b"\x01\x01\x02\x00x@\xf3\x8c'^1\tt\x16\xc1\x07)QPW\x19d\xad\xa3\xef\x1c!\xe9L\x8b\xa0\xbd\xbc\x9d\x0f\xb4\x14"
        b"\x00\x00\x00~0|\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06\t*\x86H\x86\xf7\r\x01\x07\x010"
        b"\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c-\xc0&\x1f\xeb_\xdek\xca/$y\x02\x01\x10\x80;!\x99z\xbek3|\x8b"
        b"\x98\x1b\xba\x91H<\xb1X\x8c\xc7vGv\x84*\xe1\xf1B\xd4\xe5&\xa2\xa3)\x04\x1f\xad\t\x07\x90\x14\xbeQo\xa0\xff"
        b"\x1a\xc2\xa5(i\x0c4\x10\xe8\xe2\xf3\x17}\t\xd6"
    ),  # encrypted using our public-test CMK in us-west-2
    'encryption_key': b'\xb3~{,Z\x80\x7f\x82I\xe5<h\x12\x16\x7fZ\xac\xe8]\xbc\x16\x92s\x0e\xe7\xca\xd8|X\xbf\xc32',
    'mac_key': b'w\xb5O*\xa75\xbc4\x9bn}\xf4J\xa6\xfb\xb5F\xa4,\xde\x8b\xe6hkpt\xd8\\i\xef#\xce'
}
_DEFAULT_ADDITIONAL_MATERIAL_DESCRIPTION = {
    'aws-kms-ec-attr': '*keys*',
    'amzn-ddb-wrap-alg': 'kms',
    'amzn-ddb-env-alg': 'AES/256',
    'amzn-ddb-sig-alg': 'HmacSHA256/256',
    'amzn-ddb-env-key': base64.b64encode(_DERIVED_KEYS['encrypted_initial_material']).decode('utf-8')
}
_DELEGATED_KEYS = {
    'encryption': JceNameLocalDelegatedKey(
        key=_DERIVED_KEYS['encryption_key'],
        algorithm='AES',
        key_type=EncryptionKeyType.SYMMETRIC,
        key_encoding=KeyEncodingType.RAW
    ),
    'signing': JceNameLocalDelegatedKey(
        key=_DERIVED_KEYS['mac_key'],
        algorithm='HmacSHA256',
        key_type=EncryptionKeyType.SYMMETRIC,
        key_encoding=KeyEncodingType.RAW
    )
}


@pytest.fixture
def patch_boto3_session(mocker):
    mocker.patch.object(dynamodb_encryption_sdk.material_providers.aws_kms.boto3.session, 'Session')
    return dynamodb_encryption_sdk.material_providers.aws_kms.boto3.session.Session


@pytest.fixture
def patch_add_regional_client(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_add_regional_client')
    return AwsKmsCryptographicMaterialsProvider._add_regional_client


@pytest.fixture
def patch_generate_initial_material(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_generate_initial_material')
    AwsKmsCryptographicMaterialsProvider._generate_initial_material.return_value = (
        _DERIVED_KEYS['initial_material'],
        _DERIVED_KEYS['encrypted_initial_material']
    )
    return AwsKmsCryptographicMaterialsProvider._generate_initial_material


@pytest.fixture
def patch_decrypt_initial_material(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_decrypt_initial_material')
    AwsKmsCryptographicMaterialsProvider._decrypt_initial_material.return_value = _DERIVED_KEYS['initial_material']
    return AwsKmsCryptographicMaterialsProvider._decrypt_initial_material


@pytest.fixture
def patch_encryption_key(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_encryption_key')
    AwsKmsCryptographicMaterialsProvider._encryption_key.return_value = _DELEGATED_KEYS['encryption']
    return AwsKmsCryptographicMaterialsProvider._encryption_key


@pytest.fixture
def patch_mac_key(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_mac_key')
    AwsKmsCryptographicMaterialsProvider._mac_key.return_value = _DELEGATED_KEYS['signing']
    return AwsKmsCryptographicMaterialsProvider._mac_key


@pytest.fixture
def patch_kms_client(mocker):
    mocker.patch.object(AwsKmsCryptographicMaterialsProvider, '_client')
    AwsKmsCryptographicMaterialsProvider._client.return_value.decrypt.return_value = {
        'Plaintext': _DERIVED_KEYS['initial_material'],
        'KeyId': _KEY_ID
    }
    AwsKmsCryptographicMaterialsProvider._client.return_value.generate_data_key.return_value = {
        'Plaintext': _DERIVED_KEYS['initial_material'],
        'CiphertextBlob': _DERIVED_KEYS['encrypted_initial_material'],
        'KeyId': _KEY_ID
    }
    return AwsKmsCryptographicMaterialsProvider._client


def _kms_cmp(**custom_kwargs):
    kwargs = dict(
        key_id='test_key_id',
        botocore_session=botocore.session.Session()
    )
    kwargs.update(custom_kwargs)
    if isinstance(kwargs.get('regional_clients', None), dict):
        for region, client in kwargs['regional_clients'].items():
            if client == 'generate client':
                kwargs['regional_clients'][region] = boto3.client('kms', region='us-west-2')
    return AwsKmsCryptographicMaterialsProvider(**kwargs)


@pytest.fixture
def default_kms_cmp():
    return _kms_cmp()


@pytest.mark.parametrize('invalid_kwargs', (
    dict(description=None),
    dict(algorithm=None),
    dict(length=None)
))
def test_key_info_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        kwargs = _VALID_KEY_INFO_KWARGS.copy()
        kwargs.update(invalid_kwargs)
        KeyInfo(**kwargs)


@pytest.mark.parametrize(
    'material_description, description_key, default_algorithm, default_key_length, expected_kwargs',
    (
        (
            {'a_key': 'algorithm_name/1234'},
            'a_key',
            'default_name',
            9999,
            dict(
                description='algorithm_name/1234',
                algorithm='algorithm_name',
                length=1234
            )
        ),
        (
            {'a_key': 'algorithm_name'},
            'a_key',
            'default_name',
            9999,
            dict(
                description='algorithm_name',
                algorithm='algorithm_name',
                length=9999
            )
        ),
        (
            {},
            'a_key',
            'default_name',
            9999,
            dict(
                description='default_name',
                algorithm='default_name',
                length=9999
            )
        ),
    )
)
def test_key_info_from_material_description(
        material_description,
        description_key,
        default_algorithm,
        default_key_length,
        expected_kwargs
):
    expected_keyinfo = KeyInfo(**expected_kwargs)
    actual_keyinfo = KeyInfo.from_material_description(
        material_description,
        description_key,
        default_algorithm,
        default_key_length
    )

    assert actual_keyinfo == expected_keyinfo


def test_key_info_from_description_fails():
    with pytest.raises(ValueError):
        KeyInfo.from_description(description='AES')


@mock_kms
@pytest.mark.parametrize('invalid_kwargs', (
    dict(key_id=9),
    dict(botocore_session='not a botocore session'),
    dict(grant_tokens='not a tuple'),
    dict(grant_tokens=(1, 5)),
    dict(material_description='not a dict'),
    dict(material_description={2: 'value'}),
    dict(material_description={'key': 9}),
    dict(regional_clients='not a dict'),
    dict(regional_clients={3: 'generate client'}),
    dict(regional_clients={'region': 'not a client'})
))
def test_kms_cmp_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        _kms_cmp(**invalid_kwargs)


def test_loaded_key_infos():
    cmp = _kms_cmp(material_description={})

    assert cmp._content_key_info == KeyInfo.from_description(_DEFAULT_CONTENT_ENCRYPTION_ALGORITHM)
    assert cmp._signing_key_info == KeyInfo.from_description(_DEFAULT_SIGNING_ALGORITHM)
    assert cmp._regional_clients == {}


def test_add_regional_client_known_region(default_kms_cmp, patch_boto3_session):
    default_kms_cmp._regional_clients[sentinel.region] = sentinel.client

    test = default_kms_cmp._add_regional_client(sentinel.region)

    assert not patch_boto3_session.called
    assert default_kms_cmp._regional_clients[sentinel.region] is sentinel.client
    assert test is sentinel.client


def test_add_regional_client_unknown_region(default_kms_cmp, patch_boto3_session):
    default_kms_cmp._regional_clients = {}

    test = default_kms_cmp._add_regional_client(sentinel.region)

    patch_boto3_session.assert_called_once_with(
        region_name=sentinel.region,
        botocore_session=default_kms_cmp._botocore_session
    )
    patch_boto3_session.return_value.client.assert_called_once_with(
        'kms',
        config=default_kms_cmp._user_agent_adding_config
    )
    assert default_kms_cmp._regional_clients[sentinel.region] is patch_boto3_session.return_value.client.return_value
    assert test is patch_boto3_session.return_value.client.return_value


def test_client_use_region_from_session(default_kms_cmp, patch_add_regional_client):
    mock_session = MagicMock()
    mock_session.get_config_variable.return_value = sentinel.region
    default_kms_cmp._botocore_session = mock_session

    test = default_kms_cmp._client('')

    patch_add_regional_client.assert_called_once_with(sentinel.region)
    assert test is patch_add_regional_client.return_value


def test_client_use_region_from_key_id(default_kms_cmp, patch_add_regional_client):
    mock_session = MagicMock()
    mock_session.get_config_variable.return_value = sentinel.region
    default_kms_cmp._botocore_session = mock_session

    test = default_kms_cmp._client(_KEY_ID)

    patch_add_regional_client.assert_called_once_with(_REGION)
    assert test is patch_add_regional_client.return_value


def test_client_no_region_found(default_kms_cmp):
    mock_session = MagicMock()
    mock_session.get_config_variable.return_value = None
    default_kms_cmp._botocore_session = mock_session

    with pytest.raises(UnknownRegionError) as excinfo:
        default_kms_cmp._client('')

    excinfo.match(r'No region determinable from key id:*')


def test_select_id(default_kms_cmp):
    test = default_kms_cmp._select_key_id(EncryptionContext())

    assert test is default_kms_cmp._key_id


# TODO: vectorize
@pytest.mark.parametrize('attribute, expected_value', (
    ({'B': b'\x00\x01\x02\x03'}, 'AAECAw=='),
    ({'S': 'some string value'}, 'some string value'),
    ({'N': '55.2'}, '55.2')
))
def test_attribute_to_value(default_kms_cmp, attribute, expected_value):
    test = default_kms_cmp._attribute_to_value(attribute)

    assert test == expected_value


def test_attribute_to_value_wrong_type(default_kms_cmp):
    with pytest.raises(ValueError) as excinfo:
        default_kms_cmp._attribute_to_value({'NS': [{'N': '22'}]})

    excinfo.match(r'Attribute of type *')


# TODO: vectorize
@pytest.mark.parametrize('encryption_context, additional_expected_keypairs', (
    (
        EncryptionContext(table_name='example table'),
        {'*aws-kms-table*': 'example table'}
    ),
    (
        EncryptionContext(partition_key_name='partition_key', attributes={'partition_key': {'S': 'some string value'}}),
        {'partition_key': 'some string value'}
    ),
    (
        EncryptionContext(partition_key_name='partition_key', attributes={}),
        {}
    ),
    (
        EncryptionContext(sort_key_name='sort_key', attributes={'sort_key': {'N': '55.2'}}),
        {'sort_key': '55.2'}
    ),
    (
        EncryptionContext(sort_key_name='sort_key', attributes={}),
        {}
    ),
    (
        EncryptionContext(
            table_name='example table',
            partition_key_name='partition_key',
            sort_key_name='sort_key',
            attributes={
                'partition_key': {'S': 'some string value'},
                'sort_key': {'N': '55.2'}
            }
        ),
        {
            '*aws-kms-table*': 'example table',
            'partition_key': 'some string value',
            'sort_key': '55.2'
        }
    )
))
def test_kms_encryption_context(default_kms_cmp, encryption_context, additional_expected_keypairs):
    encryption_description = 'encryption_description/123'
    signing_description = 'signing_description/123'
    expected_keypairs = {
        '*amzn-ddb-env-alg*': encryption_description,
        '*amzn-ddb-sig-alg*': signing_description
    }
    expected_keypairs.update(additional_expected_keypairs)

    test = default_kms_cmp._kms_encryption_context(encryption_context, encryption_description, signing_description)

    assert test == expected_keypairs


def test_generate_initial_material(default_kms_cmp, patch_kms_client):
    default_kms_cmp._key_id = _KEY_ID

    test = default_kms_cmp._generate_initial_material(EncryptionContext())
    assert test == (_DERIVED_KEYS['initial_material'], _DERIVED_KEYS['encrypted_initial_material'])


def test_generate_initial_material_fail(default_kms_cmp, patch_kms_client):
    default_kms_cmp._key_id = _KEY_ID
    patch_kms_client.return_value.generate_data_key.side_effect = botocore.exceptions.ClientError({}, '')

    with pytest.raises(WrappingError) as excinfo:
        default_kms_cmp._generate_initial_material(EncryptionContext())

    excinfo.match('Failed to generate materials using AWS KMS')


def test_decrypt_initial_material(default_kms_cmp, patch_kms_client):
    default_kms_cmp._key_id = _KEY_ID

    test = default_kms_cmp._decrypt_initial_material(EncryptionContext(
        material_description=_DEFAULT_ADDITIONAL_MATERIAL_DESCRIPTION
    ))

    assert test == _DERIVED_KEYS['initial_material']


def test_decrypt_initial_material_fail(default_kms_cmp, patch_kms_client):
    default_kms_cmp._key_id = _KEY_ID
    patch_kms_client.return_value.decrypt.side_effect = botocore.exceptions.ClientError({}, '')

    with pytest.raises(UnwrappingError) as excinfo:
        default_kms_cmp._decrypt_initial_material(EncryptionContext(
            material_description=_DEFAULT_ADDITIONAL_MATERIAL_DESCRIPTION
        ))

    excinfo.match('Failed to unwrap AWS KMS protected materials')


# TODO: vectorize
@pytest.mark.parametrize('description, method_name, key_name', (
    ('AES/256', '_encryption_key', 'encryption_key'),
    ('HmacSHA256/256', '_mac_key', 'mac_key')
))
def test_derive_encryption_key(default_kms_cmp, description, method_name, key_name):
    key_info = KeyInfo.from_description(description)

    test = getattr(default_kms_cmp, method_name)(
        initial_material=_DERIVED_KEYS['initial_material'],
        key_info=key_info
    )

    assert test.key == _DERIVED_KEYS[key_name]


def test_decryption_materials(default_kms_cmp, patch_decrypt_initial_material):
    material_description = {'some': 'data'}
    encryption_context = EncryptionContext(material_description=material_description)
    test = default_kms_cmp.decryption_materials(encryption_context)

    assert test.verification_key == _DELEGATED_KEYS['signing']
    assert test.decryption_key == _DELEGATED_KEYS['encryption']
    assert test.material_description == material_description


def test_encryption_materials(default_kms_cmp, patch_generate_initial_material):
    material_description = {'some': 'data'}
    encryption_context = EncryptionContext(material_description=material_description)
    test = default_kms_cmp.encryption_materials(encryption_context)

    expected_material_description = material_description.copy()
    expected_material_description.update(_DEFAULT_ADDITIONAL_MATERIAL_DESCRIPTION)
    assert test.signing_key == _DELEGATED_KEYS['signing']
    assert test.encryption_key == _DELEGATED_KEYS['encryption']
    assert test.material_description == expected_material_description
