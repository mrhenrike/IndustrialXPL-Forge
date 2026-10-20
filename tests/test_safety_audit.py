"""Tests for DestructiveGate safety audit."""


from industrialxpl.core.safety_audit import (
    DestructiveGate,
    OperationType,
    RiskLevel,
    SafetyDecision,
)


class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.PASSIVE.value == "passive"
        assert RiskLevel.CRITICAL.value == "critical"


class TestOperationType:
    def test_read_register(self):
        assert OperationType.READ_REGISTER.value == "read_register"

    def test_plc_stop(self):
        assert OperationType.PLC_STOP.value == "plc_stop"


class TestDestructiveGate:
    def test_passive_auto_approved(self):
        gate = DestructiveGate()
        result = gate.evaluate(OperationType.READ_REGISTER)
        assert result.allowed is True
        assert result.risk == RiskLevel.PASSIVE

    def test_low_auto_approved(self):
        gate = DestructiveGate()
        result = gate.evaluate(OperationType.SCAN_DISCOVERY)
        assert result.allowed is True
        assert result.risk == RiskLevel.LOW

    def test_critical_blocked(self):
        gate = DestructiveGate()
        result = gate.evaluate(OperationType.PLC_STOP, target="PLC-01")
        assert result.allowed is False
        assert result.requires_confirmation is True
        assert "CRITICAL" in result.reason

    def test_critical_firmware_blocked(self):
        gate = DestructiveGate()
        result = gate.evaluate(OperationType.FIRMWARE_UPLOAD)
        assert result.allowed is False
        assert result.risk == RiskLevel.CRITICAL

    def test_medium_requires_confirmation(self):
        gate = DestructiveGate()
        result = gate.evaluate(OperationType.WRITE_REGISTER)
        assert result.allowed is False
        assert result.requires_confirmation is True

    def test_custom_max_auto(self):
        gate = DestructiveGate(max_auto_approve=RiskLevel.MEDIUM)
        result = gate.evaluate(OperationType.WRITE_REGISTER)
        assert result.allowed is True

    def test_confirm_fn_approves(self):
        gate = DestructiveGate(
            confirm_fn=lambda op, risk: True,
        )
        result = gate.evaluate(OperationType.WRITE_REGISTER)
        assert result.allowed is True

    def test_confirm_fn_denies(self):
        gate = DestructiveGate(
            confirm_fn=lambda op, risk: False,
        )
        result = gate.evaluate(OperationType.WRITE_REGISTER)
        assert result.allowed is False

    def test_audit_log(self):
        gate = DestructiveGate()
        gate.evaluate(OperationType.READ_REGISTER)
        gate.evaluate(OperationType.SCAN_DISCOVERY)
        assert len(gate.audit_log) == 2

    def test_clear_log(self):
        gate = DestructiveGate()
        gate.evaluate(OperationType.READ_REGISTER)
        gate.clear_log()
        assert len(gate.audit_log) == 0

    def test_high_risk_operations(self):
        gate = DestructiveGate()
        for op in [
            OperationType.FORCE_OUTPUT,
            OperationType.PLC_RUN,
            OperationType.CONFIG_CHANGE,
        ]:
            result = gate.evaluate(op)
            assert result.risk == RiskLevel.HIGH


class TestSafetyDecision:
    def test_dataclass_fields(self):
        d = SafetyDecision(
            operation=OperationType.READ_REGISTER,
            risk=RiskLevel.PASSIVE,
            allowed=True,
            reason="ok",
        )
        assert d.requires_confirmation is False
