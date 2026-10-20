"""Tests for ICS Cyber Kill Chain knowledge module."""

import pytest

from industrialxpl.modules.assessment.threat_intel.ics_kill_chain import (
    Exploit as KillChain,
    _KILL_CHAIN_STAGES,
)


class TestKillChainMetadata:
    def test_info_name(self):
        e = KillChain()
        info = e.get_info()
        assert "Kill Chain" in info["name"] or "kill chain" in info["name"].lower()

    def test_has_authors(self):
        e = KillChain()
        assert len(e.get_info()["authors"]) > 0


class TestKillChainStages:
    def test_stage_count(self):
        # ICS kill chain typically has 14 stages (Dragos/SANS model)
        assert len(_KILL_CHAIN_STAGES) >= 10

    def test_stages_have_required_fields(self):
        for stage in _KILL_CHAIN_STAGES:
            assert "stage" in stage
            assert "name" in stage
            assert "description" in stage
            assert "mitre" in stage

    def test_stages_numbered_sequentially(self):
        nums = [s["stage"] for s in _KILL_CHAIN_STAGES]
        assert nums == list(range(1, len(nums) + 1))

    def test_first_stage_is_recon(self):
        assert _KILL_CHAIN_STAGES[0]["name"] == "Reconnaissance"

    def test_mitre_references_are_lists(self):
        for stage in _KILL_CHAIN_STAGES:
            assert isinstance(stage["mitre"], list)
            assert len(stage["mitre"]) > 0

    def test_stages_have_examples(self):
        for stage in _KILL_CHAIN_STAGES:
            if "examples" in stage:
                assert isinstance(stage["examples"], dict)

    def test_weaponization_stage(self):
        stage2 = _KILL_CHAIN_STAGES[1]
        assert stage2["stage"] == 2
        assert stage2["name"] == "Weaponization"

    def test_delivery_stage(self):
        stage3 = _KILL_CHAIN_STAGES[2]
        assert stage3["stage"] == 3
        assert stage3["name"] == "Delivery"

    def test_known_malware_in_examples(self):
        all_examples = {}
        for s in _KILL_CHAIN_STAGES:
            if "examples" in s:
                all_examples.update(s["examples"])
        # At least one of the well-known ICS malware families should appear
        known = {"Stuxnet", "TRITON", "Industroyer", "FrostyGoop"}
        found = known.intersection(all_examples.keys())
        assert len(found) > 0, f"Expected at least one of {known} in examples"
