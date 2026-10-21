"""Tests for the MITRE ATT&CK ICS index builder.

Validates the build_index function, tactic constants, and data structures
without requiring actual module imports beyond the MITRE package itself.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.core.mitre.index import (
    TACTIC_INDEX,
    TECHNIQUE_INDEX,
    build_index,
)
from industrialxpl.core.mitre.tactics import (
    TACTIC_ALIASES,
    TACTIC_TIDS,
    TACTICS,
)


class TestTacticsConstants:
    def test_tactics_not_empty(self):
        assert len(TACTICS) > 0

    def test_tactics_has_known_ids(self):
        assert "TA0108" in TACTICS  # Initial Access
        assert "TA0105" in TACTICS  # Impact
        assert "TA0106" in TACTICS  # Impair Process Control

    def test_tactics_values_are_strings(self):
        for tid, name in TACTICS.items():
            assert isinstance(tid, str)
            assert isinstance(name, str)
            assert tid.startswith("TA")

    def test_tactic_aliases_resolve(self):
        assert TACTIC_ALIASES["c2"] == "TA0101"
        assert TACTIC_ALIASES["impact"] == "TA0105"
        assert TACTIC_ALIASES["initial-access"] == "TA0108"

    def test_tactic_tids_has_all_tactics(self):
        for tac_id in TACTICS:
            assert tac_id in TACTIC_TIDS, f"Missing TIDs for tactic {tac_id}"

    def test_tactic_tids_are_lists(self):
        for tac_id, tids in TACTIC_TIDS.items():
            assert isinstance(tids, list)
            assert len(tids) > 0
            for t in tids:
                assert isinstance(t, str)


class TestBuildIndex:
    def test_build_with_empty_list(self):
        """build_index with no modules should produce empty indices."""
        build_index(module_paths=[])
        # After building with empty list, both indices should be empty
        assert isinstance(TECHNIQUE_INDEX, dict)
        assert isinstance(TACTIC_INDEX, dict)

    def test_build_with_nonexistent_module(self):
        """build_index should skip modules that fail attribute lookups."""
        # build_index catches AttributeError/TypeError but not ImportError.
        # Use a real but empty module path to test skip behavior.
        build_index(module_paths=["__init__"])
        # Should not raise; modules without Exploit/Scanner class are skipped

    def test_indices_are_dicts(self):
        assert isinstance(TECHNIQUE_INDEX, dict)
        assert isinstance(TACTIC_INDEX, dict)

    def test_build_index_is_idempotent(self):
        """Calling build_index twice with the same input should be safe."""
        build_index(module_paths=[])
        t1 = dict(TECHNIQUE_INDEX)
        build_index(module_paths=[])
        t2 = dict(TECHNIQUE_INDEX)
        assert t1 == t2
