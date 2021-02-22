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
from functools import partial

import pytest

from dynamodb_encryption_sdk.material_providers.aws_kms import AwsKmsCryptographicMaterialsProvider

# convenience imports
try:
    from ..functional import hypothesis_strategies  # noqa=F401 pylint: disable=unused-import
    from ..functional import functional_test_utils
except (ImportError, ValueError, SystemError):
    if "AWS_ENCRYPTION_SDK_EXAMPLES_TESTING" not in os.environ:
        raise

AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
AWS_KMS_MRK_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID"
AWS_KMS_MRK_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_2"
DDB_TABLE_NAME = "DDB_ENCRYPTION_CLIENT_TEST_TABLE_NAME"


def cmk_arn_value(env_variable=AWS_KMS_KEY_ID):
    """Retrieve the target CMK ARN from environment variable."""
    arn = os.environ.get(env_variable, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                env_variable
            )
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for integration tests must be a key not an alias")


@pytest.fixture
def cmk_arn():
    """As of Pytest 4.0.0, fixtures cannot be called directly."""
    return cmk_arn_value(AWS_KMS_KEY_ID)


@pytest.fixture
def cmk_mrk_arn():
    """As of Pytest 4.0.0, fixtures cannot be called directly."""
    return cmk_arn_value(AWS_KMS_MRK_KEY_ID)


@pytest.fixture
def second_cmk_mrk_arn():
    """As of Pytest 4.0.0, fixtures cannot be called directly."""
    return cmk_arn_value(AWS_KMS_MRK_KEY_ID_2)


def _build_kms_cmp(require_attributes):
    inner_cmp = AwsKmsCryptographicMaterialsProvider(key_id=cmk_arn_value())
    if require_attributes:
        return functional_test_utils.PassThroughCryptographicMaterialsProviderThatRequiresAttributes(inner_cmp)

    return inner_cmp


def set_parameterized_kms_cmps(metafunc, require_attributes=True):

    if "all_aws_kms_cmp_builders" in metafunc.fixturenames:
        metafunc.parametrize(
            "all_aws_kms_cmp_builders",
            (pytest.param(partial(_build_kms_cmp, require_attributes), id="Standard KMS CMP"),),
        )


@pytest.fixture
def ddb_table_name():
    """Retrieve the target DynamoDB table from environment variable."""
    try:
        return os.environ[DDB_TABLE_NAME]
    except KeyError:
        raise ValueError(
            (
                "Environment variable '{}' must be set to the correct DynamoDB table name"
                " for integration tests to run"
            ).format(DDB_TABLE_NAME)
        )


@pytest.fixture
def temp_metastore():
    metastore, table_name = functional_test_utils.build_metastore()
    yield metastore
    functional_test_utils.delete_metastore(table_name)
