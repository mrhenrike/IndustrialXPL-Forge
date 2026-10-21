"""Regression test: no bare 'except Exception' in non-vendor code.

Ensures that all exception handlers use specific exception types
rather than the broad 'except Exception' catch-all, which can mask
bugs and violate the project's exception-typing policy.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Pattern matches "except Exception" with optional alias (as e, as exc, etc.)
_BROAD_EXCEPT_RE = re.compile(r"^\s*except\s+Exception\b")

# Directories excluded from the check
_EXCLUDED = {"resources", "vendor", "__pycache__"}


def _should_skip(path: Path) -> bool:
    return any(part in _EXCLUDED for part in path.parts)


def test_no_bare_except_exception():
    """No 'except Exception' should exist in industrialxpl/ (excluding vendor)."""
    pkg_dir = ROOT / "industrialxpl"
    assert pkg_dir.is_dir(), f"Package directory not found: {pkg_dir}"

    violations = []
    for py_file in sorted(pkg_dir.rglob("*.py")):
        if _should_skip(py_file):
            continue
        text = py_file.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if _BROAD_EXCEPT_RE.match(line):
                rel = py_file.relative_to(ROOT)
                violations.append(f"{rel}:{lineno}: {line.strip()}")

    assert violations == [], (
        f"Found {len(violations)} bare 'except Exception' handler(s):\n"
        + "\n".join(violations)
    )
