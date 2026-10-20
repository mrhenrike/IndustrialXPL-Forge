"""Tests for IEC 62443 compliance engine."""


import pytest

from industrialxpl.core.compliance import (
    ComplianceCheck,
    IEC62443Engine,
    SecurityLevel,
)
from industrialxpl.core.compliance.iec62443 import (
    FOUNDATIONAL_REQUIREMENTS,
    ZONE_CONDUIT_TYPES,
    checks_by_category,
    checks_for_level,
    zone_security_level,
)


class TestSecurityLevel:
    def test_values(self):
        assert SecurityLevel.SL0.value == 0
        assert SecurityLevel.SL4.value == 4

    def test_all_levels(self):
        assert len(SecurityLevel) == 5


class TestIEC62443Engine:
    def test_baseline_loaded(self):
        engine = IEC62443Engine()
        assert len(engine.checks) > 0
        assert "SR 1.1" in engine.checks

    def test_evaluate_pass(self):
        engine = IEC62443Engine()
        result = engine.evaluate("SR 1.1", passed=True, evidence="auth enabled")
        assert result.passed is True
        assert result.requirement_id == "SR 1.1"
        assert result.evidence == "auth enabled"

    def test_evaluate_fail(self):
        engine = IEC62443Engine()
        result = engine.evaluate(
            "SR 5.1",
            passed=False,
            remediation="Implement VLAN segmentation",
        )
        assert result.passed is False
        assert "VLAN" in result.remediation

    def test_unknown_requirement(self):
        engine = IEC62443Engine()
        with pytest.raises(KeyError, match="Unknown requirement"):
            engine.evaluate("SR 99.99", passed=True)

    def test_compliance_score_empty(self):
        engine = IEC62443Engine()
        assert engine.compliance_score() == 0.0

    def test_compliance_score_full(self):
        engine = IEC62443Engine()
        for req_id in list(engine.checks.keys())[:4]:
            engine.evaluate(req_id, passed=True)
        assert engine.compliance_score() == 100.0

    def test_compliance_score_partial(self):
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 1.2", passed=False)
        assert engine.compliance_score() == 50.0

    def test_gaps(self):
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 1.2", passed=False)
        gaps = engine.gaps()
        assert len(gaps) == 1
        assert gaps[0].requirement_id == "SR 1.2"

    def test_results_by_level(self):
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 3.3", passed=False)
        sl1 = engine.results_by_level(SecurityLevel.SL1)
        sl2 = engine.results_by_level(SecurityLevel.SL2)
        assert len(sl1) == 1
        assert len(sl2) == 1

    def test_add_custom_check(self):
        engine = IEC62443Engine()
        custom = ComplianceCheck(
            requirement_id="CUSTOM-1",
            title="Custom check",
            description="Test",
            security_level=SecurityLevel.SL3,
        )
        engine.add_check(custom)
        assert "CUSTOM-1" in engine.checks

    def test_reset(self):
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.reset()
        assert engine.results() == []


class TestIEC62443Helpers:
    def test_foundational_requirements(self):
        assert "FR1" in FOUNDATIONAL_REQUIREMENTS
        assert len(FOUNDATIONAL_REQUIREMENTS) == 7

    def test_zone_types(self):
        assert "safety" in ZONE_CONDUIT_TYPES
        assert "enterprise" in ZONE_CONDUIT_TYPES

    def test_checks_for_level(self):
        engine = IEC62443Engine()
        sl1_checks = checks_for_level(engine.checks, SecurityLevel.SL1)
        assert len(sl1_checks) > 0
        for c in sl1_checks:
            assert c.security_level.value <= 1

    def test_checks_by_category(self):
        engine = IEC62443Engine()
        iac_checks = checks_by_category(engine.checks, "FR1")
        assert len(iac_checks) >= 3
        for c in iac_checks:
            assert c.category.startswith("FR1")

    def test_zone_security_level_safety(self):
        assert zone_security_level("safety") == SecurityLevel.SL4

    def test_zone_security_level_enterprise(self):
        assert zone_security_level("enterprise") == SecurityLevel.SL1

    def test_zone_security_level_unknown(self):
        assert zone_security_level("unknown") == SecurityLevel.SL1
