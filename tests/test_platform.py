"""Tests for industrialxpl.core.platform runtime checks."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.core.platform import is_linux


def test_is_linux_returns_bool():
    result = is_linux()
    assert isinstance(result, bool)


def test_is_linux_matches_platform():
    expected = sys.platform == "linux"
    assert is_linux() == expected
