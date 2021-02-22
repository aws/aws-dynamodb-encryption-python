"""Helper utilities for use while testing examples."""
import os
import sys

os.environ["AWS_ENCRYPTION_SDK_EXAMPLES_TESTING"] = "yes"
sys.path.extend([os.sep.join([os.path.dirname(__file__), "..", "..", "test", "integration"])])

from integration_test_utils import cmk_arn, cmk_mrk_arn, ddb_table_name, second_cmk_mrk_arn  # noqa pylint: disable=unused-import
