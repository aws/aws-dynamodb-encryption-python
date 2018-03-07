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
""""""
from enum import Enum

from dynamodb_encryption_sdk.exceptions import JceTransformationError

__all__ = ('JavaBridge',)


class JavaBridge(Enum):
    """Bridge the gap between Java StandardNames and Python objects.
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
    """
    def register(self):
        """Register an enum instance with a class for later retrieval by Java name."""
        self.__rlookup__[self.java_name] = self

    @classmethod
    def from_name(cls, java_name):
        """Returns the correct members based on the Java standard name.

        :param str java_name: Java bridge ID name
        :returns: Class instance with name member_name
        :rtype: varies
        :raises JceTransformationError: if unknown member name
        """
        try:
            return cls.__rlookup__[java_name]
        except KeyError:
            raise JceTransformationError('Unknown {type}: {name}'.format(
                type=cls.__name__,
                name=java_name
            ))
