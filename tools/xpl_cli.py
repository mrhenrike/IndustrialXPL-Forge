"""xpl_cli - forward to canonical XPL-Suite implementation.

Falls back to inline copy when the suite root is not adjacent (standalone install).
"""
from __future__ import annotations

import sys
from pathlib import Path

_SUITE_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if _SUITE_TOOLS.is_dir() and str(_SUITE_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SUITE_TOOLS))

try:
    from xpl_cli import (  # noqa: F401
        ProductInfo,
        bootstrap,
        print_banner,
        print_help,
        print_version,
        resolve_mode,
        run_doctor,
    )
except ImportError:
    # Standalone install fallback - import from this forge's own copy
    raise ImportError(
        "xpl_cli canonical not found at suite root. "
        "Re-clone XPL-Suite or install embedxpl for the shared tools."
    )

