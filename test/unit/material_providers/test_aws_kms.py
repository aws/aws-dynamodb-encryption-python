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
import boto3
import botocore.session
from moto import mock_kms
import pytest

from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]


def build_cmp(**custom_kwargs):
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
def test_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        build_cmp(**invalid_kwargs)
