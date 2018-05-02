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
"""Custom validators for ``attrs``.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""

__all__ = ('dictionary_validator', 'iterable_validator')


def dictionary_validator(key_type, value_type):
    """Validator for ``attrs`` that performs deep type checking of dictionaries."""

    def _validate_dictionary(instance, attribute, value):
        # pylint: disable=unused-argument
        """Validate that a dictionary is structured as expected.

        :raises TypeError: if ``value`` is not a dictionary
        :raises TypeError: if ``value`` keys are not all of ``key_type`` type
        :raises TypeError: if ``value`` values are not all of ``value_type`` type
        """
        if not isinstance(value, dict):
            raise TypeError('"{}" must be a dictionary'.format(attribute.name))

        for key, data in value.items():
            if not isinstance(key, key_type):
                raise TypeError('"{name}" dictionary keys must be of type "{type}"'.format(
                    name=attribute.name,
                    type=key_type
                ))

            if not isinstance(data, value_type):
                raise TypeError('"{name}" dictionary values must be of type "{type}"'.format(
                    name=attribute.name,
                    type=value_type
                ))

    return _validate_dictionary


def iterable_validator(iterable_type, member_type):
    """Validator for ``attrs`` that performs deep type checking of iterables."""

    def _validate_tuple(instance, attribute, value):
        # pylint: disable=unused-argument
        """Validate that a dictionary is structured as expected.

        :raises TypeError: if ``value`` is not of ``iterable_type`` type
        :raises TypeError: if ``value`` members are not all of ``member_type`` type
        """
        if not isinstance(value, iterable_type):
            raise TypeError('"{name}" must be a {type}'.format(
                name=attribute.name,
                type=iterable_type
            ))

        for member in value:
            if not isinstance(member, member_type):
                raise TypeError('"{name}" members must all be of type "{type}"'.format(
                    name=attribute.name,
                    type=member_type
                ))

    return _validate_tuple


def callable_validator(instance, attribute, value):
    # pylint: disable=unused-argument
    """Validate that an attribute value is callable.

    :raises TypeError: if ``value`` is not callable
    """
    if not callable(value):
        raise TypeError('"{name}" value "{value}" must be callable'.format(
            name=attribute.name,
            value=value
        ))
