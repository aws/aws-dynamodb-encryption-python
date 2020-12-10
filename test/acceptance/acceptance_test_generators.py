# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Tools for (re)generating cipherexts for use in interoperability tests."""

import base64
import json
import os
from collections import defaultdict
from test.acceptance.acceptance_test_utils import (
    _SCENARIO_FILE,
    _build_cmp,
    _build_plaintext_items,
    _filename_from_uri,
    _load_keys,
)

import boto3
import botocore
import pytest
from moto import mock_dynamodb2

from dynamodb_encryption_sdk import EncryptedTable
from dynamodb_encryption_sdk.material_providers.store.meta import MetaStore
from dynamodb_encryption_sdk.structures import TableIndex, TableInfo
from dynamodb_encryption_sdk.transform import ddb_to_dict, dict_to_ddb


def load_scenarios(online):
    """Load scenarios for which we should generate ciphertexts to be used in interopability tests.

    Inspired by the similarly named utility in acceptance_test_utils, but that one is (currently) specialized
    for preparing only for decrypting existing vectors. In the future we may be able to extract common functionality
    into a shared method.
    """
    # pylint: disable=too-many-locals
    with open(_SCENARIO_FILE) as f:
        scenarios = json.load(f)
    keys_file = _filename_from_uri(scenarios["keys"])
    keys = _load_keys(keys_file)
    for scenario in scenarios["scenarios"]:
        if (not online and scenario["network"]) or (online and not scenario["network"]):
            continue

        plaintext_file = _filename_from_uri(scenario["plaintext"])
        table_data = _build_plaintext_items(plaintext_file, scenario["version"])

        ciphertext_file = _filename_from_uri(scenario["ciphertext"])

        materials_provider, decrypt_key_name, verify_key_name = _build_cmp(scenario, keys)

        metastore_info = scenario.get("metastore", None)

        test_language = os.path.basename(os.path.dirname(ciphertext_file))
        if test_language != "python":
            # Only allow generation of ciphertexts for Python
            continue

        yield pytest.param(
            materials_provider,
            table_data,
            ciphertext_file,
            metastore_info,
            id="{version}-{provider}-{decrypt_key}-{verify_key}".format(
                version=scenario["version"],
                provider=scenario["provider"],
                decrypt_key=decrypt_key_name,
                verify_key=verify_key_name,
            ),
        )


def _generate(materials_provider, table_data, ciphertext_file, metastore_info):
    # pylint: disable=too-many-locals
    client = boto3.client("dynamodb", region_name="us-west-2")
    data_table_output = defaultdict(list)
    metastore_output = defaultdict(list)
    metatable = _create_meta_table(client, metastore_info)

    for table_name in table_data:
        table = None
        try:
            table_index = table_data[table_name]["index"]
            table_index_types = table_data[table_name]["index_types"]
            table_items = table_data[table_name]["items"]

            _create_data_table(client, table_name, table_index, table_index_types)
            table = boto3.resource("dynamodb", region_name="us-west-2").Table(table_name)
            table.wait_until_exists()

            cmp = materials_provider()

            table_info = TableInfo(
                name=table_name,
                primary_index=TableIndex(partition=table_index["partition"], sort=table_index.get("sort", None)),
            )

            for plaintext_item in table_items:
                source_item = plaintext_item["item"]
                item_key = {table_info.primary_index.partition: source_item[table_info.primary_index.partition]}
                if table_info.primary_index.sort is not None:
                    item_key[table_info.primary_index.sort] = source_item[table_info.primary_index.sort]

                attribute_actions = plaintext_item["action"]

                e_table = EncryptedTable(
                    table=table,
                    materials_provider=cmp,
                    table_info=table_info,
                    attribute_actions=attribute_actions,
                    auto_refresh_table_indexes=False,
                )
                e_table.put_item(Item=ddb_to_dict(source_item))
                retrieved_item = table.get_item(Key=ddb_to_dict(item_key))
                parsed_item = dict_to_ddb(retrieved_item["Item"])
                data_table_output[table_name].append(ddb_to_json(parsed_item))

        finally:
            if table:
                table.delete()

    with open(ciphertext_file, "w") as outfile:
        json.dump(data_table_output, outfile, indent=4)

    if metatable:
        # Assume exactly one entry in metastore table
        wrapping_key = dict_to_ddb(metatable.scan()["Items"][0])
        metastore_output[metastore_info["table_name"]].append(ddb_to_json(wrapping_key))

        metastore_ciphertext_file = _filename_from_uri(metastore_info["ciphertext"])
        with open(metastore_ciphertext_file, "w") as outfile:
            json.dump(metastore_output, outfile, indent=4)

        metatable.delete()


def ddb_to_json(ddb_item):
    """Convert a DDB item to a JSON-compatible format.

    For now, this means encoding any binary fields as base64.
    """
    json_item = ddb_item.copy()
    for attribute in json_item:
        for value in json_item[attribute]:
            if value == "B":
                json_item[attribute][value] = base64.b64encode(json_item[attribute][value]).decode("utf-8")

    return json_item


def _create_data_table(client, table_name, table_index, table_index_types):
    """Create DDB tables to be used for generating test vectors."""
    try:
        attribute_definitions = [
            {"AttributeName": table_index["partition"], "AttributeType": table_index_types["partition"]}
        ]
        key_schema = [{"AttributeName": table_index["partition"], "KeyType": "HASH"}]
        if "sort" in table_index:
            attribute_definitions.append(
                {"AttributeName": table_index["sort"], "AttributeType": table_index_types["sort"]}
            )
            key_schema.append({"AttributeName": table_index["sort"], "KeyType": "RANGE"})
        client.create_table(
            TableName=table_name,
            AttributeDefinitions=attribute_definitions,
            KeySchema=key_schema,
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
    except botocore.exceptions.ClientError:
        raise Exception("Could not create table")


def _create_meta_table(client, metastore_info):
    """Create DDB table for use with a MetaStore."""
    if metastore_info is None:
        return None

    metatable_name = metastore_info["table_name"]
    MetaStore.create_table(client, metatable_name, 5, 5)
    metatable = boto3.resource("dynamodb", region_name="us-west-2").Table(metastore_info["table_name"])
    metatable.wait_until_exists()
    return metatable


@mock_dynamodb2
@pytest.mark.generate
@pytest.mark.parametrize(
    "materials_provider, table_data, ciphertext_file, metastore_info",
    load_scenarios(online=False),
)
def test_generate_ciphertexts_offline(materials_provider, table_data, ciphertext_file, metastore_info):
    return _generate(materials_provider, table_data, ciphertext_file, metastore_info)


@pytest.mark.generate
@pytest.mark.parametrize(
    "materials_provider, table_data, ciphertext_file, metastore_info",
    load_scenarios(online=True),
)
def test_generate_ciphertexts_online(materials_provider, table_data, ciphertext_file, metastore_info):
    return _generate(materials_provider, table_data, ciphertext_file, metastore_info)
