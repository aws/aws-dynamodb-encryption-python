*********
Changelog
*********

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
