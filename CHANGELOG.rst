*********
Changelog
*********

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
