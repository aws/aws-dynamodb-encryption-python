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
"""Helper utilities for integration tests."""
import os
import sys

import pytest

from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider

sys.path.append(os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    '..',
    'functional'
))

# Convenience imports
import functional_test_utils  # noqa: E402,F401,I100
import hypothesis_strategies  # noqa: E402,F401,I100

AWS_KMS_KEY_ID = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID'


@pytest.fixture
def cmk_arn():
    """Retrieve the target CMK ARN from environment variable."""
    arn = os.environ.get(AWS_KMS_KEY_ID, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        )
    if arn.startswith('arn:') and ':alias/' not in arn:
        return arn
    raise ValueError('KMS CMK ARN provided for integration tests must be a key not an alias')


@pytest.fixture
def aws_kms_cmp():
    return AwsKmsCryptographicMaterialsProvider(key_id=cmk_arn())
