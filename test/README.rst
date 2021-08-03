********************************************
dynamodb-encryption-client Integration Tests
********************************************

In order to run these integration tests successfully, these things which must be configured.

#. These tests assume that AWS credentials are available in one of the
   `automatically discoverable credential locations`_.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID`` environment variable
   must be set to a valid `AWS KMS CMK ARN`_ that can be used by the available credentials.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID`` and ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_2`` environment variables
   must be set to two related AWS KMS Multi-Region key ids in different regions.
#. The ``DDB_ENCRYPTION_CLIENT_TEST_TABLE_NAME`` environment variable must be set to a valid
   DynamoDB table name, in the default region, to which the discoverable credentials have
   read, write, and describe permissions.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS CMK ARN: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html

Updating Upstream Requirements
==============================

The purpose of the upstream requirements files is to provide a stable list of
packages for dependencies to run downstream tests of the DynamoDB Encryption
Client. In order to update the upstream requirements in `upstream-requirements-py37.txt`,
run these commands::

    $ tox -e freeze-upstream-requirements-py37

Test them using::

    $ tox -e test-upstream-requirements-py37

