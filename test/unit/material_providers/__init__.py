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
"""Unit test for ``dynamodb_encryption_sdk.material_providers``."""
import pytest

from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize('method, message', (
    ('decryption_materials', 'No decryption materials available'),
    ('encryption_materials', 'No encryption materials available')
))
def test_no_materials(method, message):
    empty_cmp = CryptographicMaterialsProvider(
        decryption_materials=None,
        encryption_materials=None
    )

    with pytest.raises(AttributeError) as excinfo:
        getattr(empty_cmp, method)(None)

    excinfo.match(message)
