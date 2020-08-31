# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Load testing using MostRecentProvider and MetaStore."""
import pytest

from ..integration_test_utils import ddb_table_name  # noqa=F401 pylint: disable=unused-import
from ..integration_test_utils import temp_metastore  # noqa=F401 pylint: disable=unused-import
from ..integration_test_utils import functional_test_utils

pytestmark = [pytest.mark.integ, pytest.mark.ddb_integ]


def test_cache_use_encrypt(temp_metastore, ddb_table_name, caplog):
    functional_test_utils.check_metastore_cache_use_encrypt(temp_metastore, ddb_table_name, caplog)
