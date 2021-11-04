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
"""Unique identifiers used by the DynamoDB Encryption Client."""
import datetime
import sys
import warnings
from enum import Enum

__all__ = (
    "LOGGER_NAME",
    "CryptoAction",
    "EncryptionKeyType",
    "KeyEncodingType",
    "PythonVersionSupport",
    "check_python_version",
)

__version__ = "3.0.0"

LOGGER_NAME = "dynamodb_encryption_sdk"
USER_AGENT_SUFFIX = "DynamodbEncryptionSdkPython/{}".format(__version__)


class CryptoAction(Enum):
    """Possible actions to take on an item attribute."""

    DO_NOTHING = 0
    SIGN_ONLY = 1
    ENCRYPT_AND_SIGN = 2

    def __gt__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return not self.__lt__(other) and not self.__eq__(other)

    def __lt__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return self.value < other.value  # pylint: disable=comparison-with-callable

    def __eq__(self, other):
        # type: (CryptoAction) -> bool
        """Define CryptoAction equality."""
        return self.value == other.value  # pylint: disable=comparison-with-callable


class EncryptionKeyType(Enum):
    """Supported types of encryption keys."""

    SYMMETRIC = 0
    PRIVATE = 1
    PUBLIC = 2


class KeyEncodingType(Enum):
    """Supported key encoding schemes."""

    RAW = 0
    DER = 1
    PEM = 2


# pylint: disable=too-few-public-methods
class PythonVersionSupport:
    """Configures Python Version warnings/error messaging"""

    WARN_BELOW_MAJOR = 3
    WARN_BELOW_MINOR = 6
    ERROR_BELOW_MAJOR = 3
    ERROR_BELOW_MINOR = 6
    ERROR_DATE = datetime.datetime(year=2022, month=1, day=1)


def check_python_version(
    warn_below_major=PythonVersionSupport.WARN_BELOW_MAJOR,
    warn_below_minor=PythonVersionSupport.WARN_BELOW_MINOR,
    error_below_major=PythonVersionSupport.ERROR_BELOW_MAJOR,
    error_below_minor=PythonVersionSupport.ERROR_BELOW_MINOR,
    error_date=PythonVersionSupport.ERROR_DATE,
):
    """Checks that we are on a supported version of Python.
    Prints an error message to stderr if the Python Version is unsupported and therefore untested.
    Emits a warning if the Python version will be unsupported.
    """
    if datetime.datetime.now() > error_date and (
        sys.version_info.major < error_below_major or sys.version_info.minor < error_below_minor
    ):
        sys.stderr.write(
            "ERROR: Python {} is not supported by the aws-encryption-sdk! ".format(
                ".".join(map(str, [sys.version_info.major, sys.version_info.minor]))
            )
            + "Please upgrade to Python {} or higher.".format(".".join(map(str, [warn_below_major, warn_below_minor])))
        )
        return
    if sys.version_info.major < warn_below_major or sys.version_info.minor < warn_below_minor:
        warnings.warn(
            "Python {} support will be removed in a future release. ".format(
                ".".join(map(str, [sys.version_info.major, sys.version_info.minor]))
            )
            + "Please upgrade to Python {} or higher.".format(".".join(map(str, [warn_below_major, warn_below_minor]))),
            DeprecationWarning,
        )
