"""S2OPC lab wrapper — optional native build (Apache-2.0)."""

from __future__ import annotations

import shutil
from typing import Any


def s2opc_status() -> dict[str, Any]:
    cmake = shutil.which("cmake")
    return {
        "success": True,
        "simulate": True,
        "cmake": bool(cmake),
        "fallback": "asyncua (Python) — pip install industrialxpl-forge[ot]",
        "note": "S2OPC native build skipped when cmake absent",
        "skip_native": not cmake,
    }
