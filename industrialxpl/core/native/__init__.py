"""Native payload loader for IXF.

This module discovers and loads native payload implementations from
contrib/native-payloads/ when present (GitHub clone only -- not in PyPI).
"""

from industrialxpl.core.native.loader import NativePayloadLoader, NativePayload

__all__ = ["NativePayloadLoader", "NativePayload"]
