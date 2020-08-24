"""Types used with mypy for DynamoDB items and attributes.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
# constant naming for types so pylint: disable=invalid-name
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, AnyStr, ByteString, Dict, List, Text

    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    ATTRIBUTE = Dict[Text, Any]  # narrow this down
    ITEM = Dict[Text, ATTRIBUTE]
    RAW_ATTRIBUTE = ITEM
    NULL = bool  # DynamoDB TypeSerializer converts none to {'NULL': True}
    BOOLEAN = bool
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    NUMBER = int  # This misses long on Python 2...figure out something for this
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    STRING = AnyStr  # can be unicode but should not be bytes
    BINARY = ByteString
    BINARY_ATTRIBUTE = Dict[Text, BINARY]
    SET = List  # DynamoDB TypeSerializer converts sets into lists
    MAP = RAW_ATTRIBUTE
    LIST = List[RAW_ATTRIBUTE]
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass
