"""Repository path helpers.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
SRC_DIR = PACKAGE_DIR.parent
REPO_ROOT = SRC_DIR.parent
SCENARIOS_DIR = REPO_ROOT / "scenarios"
CATALOG_DIR = REPO_ROOT / "attacks" / "catalog"
TMP_DIR = REPO_ROOT / ".tmp"
LOG_DIR = REPO_ROOT / ".log"
RUNTIME_DIR = REPO_ROOT / "runtime"


def ensure_workspace_dirs() -> None:
    """Create workspace-local temp, log and runtime directories."""
    for path in (TMP_DIR, LOG_DIR, RUNTIME_DIR):
        path.mkdir(parents=True, exist_ok=True)
