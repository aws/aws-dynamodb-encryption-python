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
"""Test ``aws_kms_encrypted_table.py``."""
import os
import sys
sys.path.extend([  # noqa
    os.sep.join([os.path.dirname(__file__), '..', '..', 'test', 'integration']),
    os.sep.join([os.path.dirname(__file__), '..', 'src'])
])

import pytest

from aws_kms_encrypted_table import encrypt_item  # noqa
from integration_test_utils import cmk_arn, ddb_table_name  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.examples]


def test_example(cmk_arn, ddb_table_name):
    encrypt_item(ddb_table_name, cmk_arn)
