# -*- coding: utf-8 -*-
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
"""Helper resources for functional tests."""
from collections import namedtuple
from decimal import Decimal

from boto3.dynamodb.types import Binary, DYNAMODB_CONTEXT
import hypothesis
from hypothesis.strategies import binary, booleans, dictionaries, deferred, fractions, just, lists, none, sets, text

SLOW_SETTINGS = hypothesis.settings(
    suppress_health_check=(
        hypothesis.HealthCheck.too_slow,
        hypothesis.HealthCheck.data_too_large,
        hypothesis.HealthCheck.hung_test,
        hypothesis.HealthCheck.large_base_example
    ),
    timeout=hypothesis.unlimited,
    deadline=None
)
VERY_SLOW_SETTINGS = hypothesis.settings(
    SLOW_SETTINGS,
    max_examples=1000,
    max_iterations=1500
)
MAX_ITEM_BYTES = 400 * 1024 * 1024

NumberRange = namedtuple('NumberRange', ('min', 'max'))
_MIN_NUMBER = '1E-128'  # The DDB min is 1E-130, but DYNAMODB_CONTEXT Emin is -128
_MAX_NUMBER = '9.9999999999999999999999999999999999999E+125'
POSITIVE_NUMBER_RANGE = NumberRange(
    min=Decimal(_MIN_NUMBER),
    max=Decimal(_MAX_NUMBER)
)
NEGATIVE_NUMBER_RANGE = NumberRange(
    min=Decimal('-' + _MAX_NUMBER),
    max=Decimal('-' + _MIN_NUMBER)
)


ddb_string = text(min_size=1, max_size=MAX_ITEM_BYTES)
ddb_string_set = sets(ddb_string, min_size=1)


def _ddb_fraction_to_decimal(val):
    """hypothesis does not support providing a custom Context, so working around that"""
    return DYNAMODB_CONTEXT.create_decimal(Decimal(val.numerator) / Decimal(val.denominator))


_ddb_positive_numbers = fractions(
    min_value=POSITIVE_NUMBER_RANGE.min,
    max_value=POSITIVE_NUMBER_RANGE.max
).map(_ddb_fraction_to_decimal)
_ddb_negative_numbers = fractions(
    min_value=NEGATIVE_NUMBER_RANGE.min,
    max_value=NEGATIVE_NUMBER_RANGE.max
).map(_ddb_fraction_to_decimal)

ddb_number = _ddb_negative_numbers | just(Decimal('0')) | _ddb_positive_numbers
ddb_number_set = sets(ddb_number, min_size=1)

ddb_binary = binary(min_size=1, max_size=MAX_ITEM_BYTES).map(Binary)
ddb_binary_set = sets(ddb_binary, min_size=1)

ddb_boolean = booleans()
ddb_null = none()

ddb_scalar_types = (
    ddb_string
    | ddb_number
    | ddb_binary
    | ddb_boolean
    | ddb_null
)

ddb_set_types = (
    ddb_string_set
    | ddb_number_set
    | ddb_binary_set
)
# TODO: List and Map types have a max depth of 32
ddb_map_type = deferred(lambda: dictionaries(
    keys=text(),
    values=(
        ddb_scalar_types
        | ddb_set_types
        | ddb_list_type
        | ddb_map_type
    ),
    min_size=1
))
ddb_list_type = deferred(lambda: lists(
    ddb_scalar_types
    | ddb_set_types
    | ddb_list_type
    | ddb_map_type,
    min_size=1
))
ddb_document_types = ddb_map_type | ddb_list_type

ddb_attribute_values = ddb_scalar_types | ddb_set_types | ddb_list_type

ddb_items = dictionaries(
    keys=text(min_size=1, max_size=255),
    values=ddb_scalar_types | ddb_set_types | ddb_list_type
)


material_descriptions = deferred(lambda: dictionaries(
    keys=text(),
    values=text(),
    min_size=1
))
