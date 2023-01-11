*********
Changelog
*********

3.2.0 -- 2021-12-19
===================

Deprecation
-----------
The AWS DynamoDB Encryption Client for Python no longer supports Python 3.6
as of version 3.2; only Python 3.7+ is supported.

Feature
-----------
* Warn on Deprecated Python 3.6 usage

3.1.0 -- 2021-11-10
===================

Deprecation
-----------
The AWS DynamoDB Encryption Client for Python no longer supports Python 3.5
as of version 3.1; only Python 3.6+ is supported. Customers using
Python 3.5 can still use the 2.x line of the AWS DynamoDB Encryption Client for Python,
which will continue to receive security updates, in accordance
with our `Support Policy <https://github.com/aws/aws-dynamodb-encryption-python/blob/master/SUPPORT_POLICY.rst>`__.

Feature
-----------
* Warn on Deprecated Python usage
  `#368 <https://github.com/aws/aws-encryption-sdk-python/pull/368>`_
* Add Python 3.10 to CI
* Remove Python 3.5 from testing


3.0.0 -- 2021-07-15
===================

Deprecation
-----------
The AWS DynamoDB Encryption Client for Python no longer supports Python 2 or Python 3.4
as of major version 3.x; only Python 3.5+ is supported. Customers using Python 2
or Python 3.4 can still use the 2.x line of the DynamoDB Encryption Client,
which will continue to receive security updates for the next 12 months, in accordance
with our `Support Policy <https://github.com/aws/aws-dynamodb-encryption-python/blob/master/SUPPORT_POLICY.rst>`__.


2.1.0 -- 2021-07-15
===================

Deprecation Announcement
------------------------
The AWS DynamoDB Encryption Client for Python is discontinuing support for Python 2.
Future major versions of this library will drop support for Python 2 and begin to
adopt changes that are known to break Python 2.

Support for Python 3.4 will be removed at the same time. Moving forward, we will
support Python 3.5+.

Security updates will still be available for the DynamoDB Encryption Client 2.x
line for the next 12 months, in accordance with our `Support Policy <https://github.com/aws/aws-dynamodb-encryption-python/blob/master/SUPPORT_POLICY.rst>`__.


2.0.0 -- 2021-02-04
===================

Breaking Changes
----------------
Removes MostRecentProvider. MostRecentProvider is replaced by CachingMostRecentProvider as of 1.3.0.


1.3.0 -- 2021-02-04
===================
Adds the CachingMostRecentProvider and deprecates MostRecentProvider.

Time-based key reauthorization logic in MostRecentProvider did not reauthorize
the use of the key after key usage permissions were changed at the key provider
(for example AWS Key Management Service). This created the potential for keys
to be used in the DynamoDB Encryption Client after permissions to do so were revoked.

CachingMostRecentProvider replaces MostRecentProvider and provides a cache entry
TTL to reauthorize the key with the key provider.

MostRecentProvider is now deprecated, and is removed in 2.0.0. See
https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/most-recent-provider.html
for more details.


1.2.0 -- 2019-10-10
===================

Bugfixes
--------
* Fix :class:`AwsKmsCryptographicMaterialsProvider` regional clients override bug
  `#124 <https://github.com/aws/aws-dynamodb-encryption-python/issues/124>`_
  **NOTE: It is possible that this is a breaking change for you,
  depending on how you are re-using any custom botocore sessions
  that you provide to AwsKmsCryptographicMaterialsProvider.**
* Remove ``attributes`` attribute from :class:`EncryptionContext` ``str`` and ``repr`` values.
  `#127 <https://github.com/aws/aws-dynamodb-encryption-python/issues/127>`_

1.1.1 -- 2019-08-29
===================

Bugfixes
--------
* Fix :class:`EncryptedPaginator` to successfully decrypt when using :class:`AwsKmsCryptographicMaterialsProvider`
  `#118 <https://github.com/aws/aws-dynamodb-encryption-python/pull/118>`_

1.1.0 -- 2019-03-13
===================

Features
--------
* Batch write operations via the high-level helper clients now return plaintext items in ``UnprocessedItems``.
    `#107 <https://github.com/aws/aws-dynamodb-encryption-python/pull/107>`_

1.0.7 -- 2018-01-16
===================

Bugfixes
--------
* Fix :class:`MostRecentProvider` cache reuse bug.
  `#105 <https://github.com/aws/aws-dynamodb-encryption-python/pull/105>`_

1.0.6 -- 2018-01-15
===================

Bugfixes
--------
* Fix :class:`MostRecentProvider` bug in providing invalid cached results.
  `#102 <https://github.com/aws/aws-dynamodb-encryption-python/pull/102>`_

1.0.5 -- 2018-08-01
===================
* Move the ``aws-dynamodb-encryption-python`` repository from ``awslabs`` to ``aws``.

1.0.4 -- 2018-05-22
===================

Bugfixes
--------
* Fix :class:`MostRecentProvider` behavior when lock cannot be acquired.
  `#72 <https://github.com/aws/aws-dynamodb-encryption-python/issues/72>`_
* Fix :class:`MostRecentProvider` lock acquisition for Python 2.7.
  `#74 <https://github.com/aws/aws-dynamodb-encryption-python/issues/74>`_
* Fix :class:`TableInfo` secondary index storage.
  `#75 <https://github.com/aws/aws-dynamodb-encryption-python/issues/75>`_

1.0.3 -- 2018-05-03
===================

Bugfixes
--------
* Finish fixing ``MANIFEST.in``.

1.0.2 -- 2018-05-03
===================

Bugfixes
--------
* Fill out ``MANIFEST.in`` to correctly include necessary files in source build.

1.0.1 -- 2018-05-02
===================
* Add version convenience import to base namespace.

1.0.0 -- 2018-05-02
===================
* Initial public release
