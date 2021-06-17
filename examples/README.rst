#########################################
AWS DynamoDB Encryption Client Examples
#########################################

This section features examples that show you
how to use the AWS DynamoDB Encryption Client.
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

APIs
====

The AWS DynamoDB Encryption Client provides four high-level APIs: `EncryptedClient`, `EncryptedItem`,
`EncryptedResource`, and `EncryptedTable`.

You can find examples that demonstrate these APIs
in the `examples/src/dynamodb_encryption_sdk_examples <./src/dynamodb_encryption_sdk_examples>`_ directory.
Each of these examples uses AWS KMS as the materials provider.

* `How to use the EncryptedClient API <./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_client.py>`_
* `How to use the EncryptedItem API <./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_item.py>`_
* `How to use the EncryptedResource API <./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_resource.py>`_
* `How to use the EncryptedTable API <./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_table.py>`_

Material Providers
==================

To use the encryption and decryption APIs, you need to describe how you want the library to protect your data keys.
You can do this by configuring material providers. AWS KMS is the most common material provider used with the AWS DynamoDB Encryption
SDK, and each of the API examples above uses AWS KMS. This section describes the other providers that come bundled
with this library.

* `How to use the CachingMostRecentProvider <./src/dynamodb_encryption_sdk_examples/most_recent_provider_encrypted_table.py>`_
* `How to use raw symmetric wrapping keys <./src/dynamodb_encryption_sdk_examples/wrapped_symmetric_encrypted_table.py>`_
* `How to use raw asymmetric wrapping keys <./src/dynamodb_encryption_sdk_examples/wrapped_rsa_encrypted_table.py>`_

For more details on the different type of material providers, see `How to choose a cryptographic materials provider <https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/crypto-materials-providers.html>`_.

Running the examples
====================

In order to run these examples, these things must be configured:

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID`` environment variable
   must be set to a valid `AWS KMS CMK ARN`_ that can be used by the available credentials.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID`` and ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_2`` environment variables
   must be set to two related AWS KMS Multi-Region key ids in different regions.
#. The ``DDB_ENCRYPTION_CLIENT_TEST_TABLE_NAME`` environment variable must be set to a valid
   DynamoDB table name, in the default region, to which the discoverable credentials have
   read, write, and describe permissions.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS CMK ARN: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
