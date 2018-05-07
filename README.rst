############################################
Amazon DynamoDB Encryption Client for Python
############################################

.. image:: https://img.shields.io/pypi/v/dynamodb-encryption-sdk.svg
   :target: https://pypi.python.org/pypi/dynamodb-encryption-sdk
   :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/dynamodb-encryption-sdk.svg
   :target: https://pypi.org/project/dynamodb-encryption-sdk
   :alt: Supported Python Versions

.. image:: https://readthedocs.org/projects/aws-dynamodb-encryption-python/badge/?version=latest
   :target: http://aws-dynamodb-encryption-python.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://travis-ci.org/awslabs/aws-dynamodb-encryption-python.svg?branch=master
   :target: https://travis-ci.org/awslabs/aws-dynamodb-encryption-python

.. image:: https://ci.appveyor.com/api/projects/status/6mh2v0nusujldu72/branch/master?svg=true
   :target: https://ci.appveyor.com/project/mattsb42-aws/aws-dynamodb-encryption-python-v5ycc

The `Amazon DynamoDB Encryption Client for Python`_ provides client-side encryption of `Amazon
DynamoDB`_ items to help you to protect your table data before you send it to DynamoDB. It
provides an implementation of the `Amazon DynamoDB Encryption Client`_ that is fully compatible
with the `Amazon DynamoDB Encryption Client for Java`_.

You can find the latest Python documentation at `Read the Docs`_ and you can find the latest
full documents in our `primary documents`_.

You can find our source on `GitHub`_.

***************
Getting Started
***************

Required Prerequisites
======================

* Python 2.7 or 3.4+

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional
   prerequisites as detailed in the `cryptography installation guide`_ for your operating
   system.

   .. code::

       $ pip install dynamodb-encryption-sdk

Concepts
========

For a detailed description of the concepts that are important to understand when using this
client, please review our `Concepts Guide`_.


*****
Usage
*****

Helper Clients
==============

We provide helper clients that look and feel like the low level client (`EncryptedClient`_),
service resource (`EncryptedResource`_), and table resource (`EncryptedTable`_) available
from the `boto3`_ library. For most uses, once configured, these clients can be used exactly
as you would a standard client from `boto3`_, and your items will be transparently encrypted
on write and decrypted on read.

What can't I do with the helper clients?
----------------------------------------

For most uses, the helper clients (once configured) can be used as drop-in replacements for
the `boto3`_ clients. However, there are a couple cases where this is not the case.

Update Item
^^^^^^^^^^^

Because we can't know that a partial update you might be making to an item covers all
of the signed attributes in your item, we do not allow ``update_item`` on the helper clients.

This is because if you update only some of the signed attributes, then next time you try
to read that item the signature validation will fail.

Attribute Filtering
^^^^^^^^^^^^^^^^^^^

Because we can't know what attributes in an item are signed, the helper clients do not allow
any attribute filtering.

For ``get_item``, ``batch_get_item``, and ``scan``, this includes the use of ``AttributesToGet``
and ``ProjectionExpression``.

For ``scan``, this also includes the use of ``Select`` values ``SPECIFIC_ATTRIBUTES`` and
``ALL_PROJECTED_ATTRIBUTES``.

This is because if you do not retrieve all signed attributes, the signature validation will
fail.

Item Encryptor
==============

The helper clients provide a familiar interface but the actual item encryption and decryption
is handled by a low-level item encryptor. You usually will not need to interact with these
low-level functions, but for certain advanced use cases it can be useful.

If you do choose to use the item encryptor functions directly, you will need to provide a
`CryptoConfig`_ for each call.

.. code-block:: python

   >>> from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item
   >>> plaintext_item = {
   ...     'some': 'data',
   ...     'more': 5
   ... }
   >>> encrypted_item = encrypt_python_item(
   ...     item=plaintext_item,
   ...     crypto_config=my_crypto_config
   ... )
   >>> decrypted_item = decrypt_python_item(
   ...     item=encrypted_item,
   ...     crypto_config=my_crypto_config
   ... )


When should I use the item encryptor?
-------------------------------------

One example of a use case where you might want to use the item encryptor directly is when
processing items in a `DynamoDB Stream`_. Since you receive the items data directly, and
in DynamoDB JSON format, you can use the `decrypt_dynamodb_item`_ function to decrypt the
item in the stream. We also provide helper `transformation functions`_

Advanced Use
============

By default, the helper clients use your attribute actions and cryptographic materials provider
to build the `CryptoConfig`_ that is provided to the item encryptor. For some advanced use
cases, you might want to provide a custom `CryptoConfig`_ for specific operations.

All data plane operations (get item, put item, etc) on helper clients accept a ``crypto_config``
parameter in addition to all of the parameters that the underlying `boto3`_ client accepts.

If this parameter is supplied, that `CryptoConfig`_ will be used for that operation instead
of the one that the client would normally construct for you.

.. code-block:: python

    >>> from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
    >>> encrypted_table = EncryptedTable(
    ...     table=table,
    ...     materials_provider=my_crypto_materials_provider
    ... )
    >>> encrypted_table.put_item(
    ...     Item=my_standard_item
    ... )  # this uses the crypto config built by the helper
    >>> encrypted_table.put_item(
    ...     Item=my_special_item,
    ...     crypto_config=my_special_crypto_config
    ... )  # this uses my_special_crypto_config


.. _Amazon DynamoDB Encryption Client: https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/
.. _Amazon DynamoDB: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
.. _primary documents: https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/
.. _Concepts Guide: https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/concepts.html
.. _Amazon DynamoDB Encryption Client for Java: https://github.com/awslabs/aws-dynamodb-encryption-java/
.. _Amazon DynamoDB Encryption Client for Python: https://github.com/awslabs/aws-dynamodb-encryption-python/
.. _DynamoDB Stream: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html
.. _Read the Docs: http://aws-dynamodb-encryption-python.readthedocs.io/en/latest/
.. _GitHub: https://github.com/awslabs/aws-dynamodb-encryption-python/
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _boto3: https://boto3.readthedocs.io/en/latest/
.. _EncryptedClient: lib/encrypted/client.html
.. _EncryptedResource: lib/encrypted/resource.html
.. _EncryptedTable: lib/encrypted/table.html
.. _CryptoConfig: lib/encrypted/config.html
.. _decrypt_dynamodb_item: lib/encrypted/item.html#dynamodb_encryption_sdk.encrypted.item.decrypt_dynamodb_item
.. _transformation functions: lib/tools/transform.html
