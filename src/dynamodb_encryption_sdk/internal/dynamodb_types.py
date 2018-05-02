"""Types used with mypy for DynamoDB items and attributes.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, AnyStr, ByteString, Dict, List, Text

    ATTRIBUTE = Dict[Text, Any]  # TODO: narrow this down
    ITEM = Dict[Text, ATTRIBUTE]
    RAW_ATTRIBUTE = ITEM
    NULL = bool  # DynamoDB TypeSerializer converts none to {'NULL': True}
    BOOLEAN = bool
    NUMBER = int  # TODO: This misses long on Python 2...figure out something for this
    STRING = AnyStr  # TODO: can be unicode but should not be bytes
    BINARY = ByteString
    BINARY_ATTRIBUTE = Dict[Text, BINARY]
    SET = List  # DynamoDB TypeSerializer converts sets into lists
    MAP = RAW_ATTRIBUTE
    LIST = List[RAW_ATTRIBUTE]
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass
