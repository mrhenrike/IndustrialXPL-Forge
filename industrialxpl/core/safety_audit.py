"""DestructiveGate: safety audit layer for OT/ICS operations.

Classifies operations by risk level and enforces gates before
allowing potentially destructive actions against industrial targets.
"""


import logging
from dataclasses import dataclass, field
from enum import Enum
from collections.abc import Callable

logger = logging.getLogger(__name__)

__all__ = [
    "DestructiveGate",
    "OperationType",
    "RiskLevel",
    "SafetyDecision",
]


class RiskLevel(Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperationType(Enum):
    READ_REGISTER = "read_register"
    SCAN_DISCOVERY = "scan_discovery"
    WRITE_REGISTER = "write_register"
    FIRMWARE_UPLOAD = "firmware_upload"
    FORCE_OUTPUT = "force_output"
    PLC_STOP = "plc_stop"
    PLC_RUN = "plc_run"
    CONFIG_CHANGE = "config_change"
    NETWORK_RECONFIG = "network_reconfig"


OPERATION_RISK: dict[OperationType, RiskLevel] = {
    OperationType.READ_REGISTER: RiskLevel.PASSIVE,
    OperationType.SCAN_DISCOVERY: RiskLevel.LOW,
    OperationType.WRITE_REGISTER: RiskLevel.MEDIUM,
    OperationType.FIRMWARE_UPLOAD: RiskLevel.CRITICAL,
    OperationType.FORCE_OUTPUT: RiskLevel.HIGH,
    OperationType.PLC_STOP: RiskLevel.CRITICAL,
    OperationType.PLC_RUN: RiskLevel.HIGH,
    OperationType.CONFIG_CHANGE: RiskLevel.HIGH,
    OperationType.NETWORK_RECONFIG: RiskLevel.CRITICAL,
}


@dataclass
class SafetyDecision:
    operation: OperationType
    risk: RiskLevel
    allowed: bool
    reason: str
    requires_confirmation: bool = False


class DestructiveGate:
    """Evaluate whether an OT operation should proceed.

    Default policy blocks CRITICAL without explicit authorization
    and warns on HIGH. Custom policies can override via callbacks.
    """

    def __init__(
        self,
        max_auto_approve: RiskLevel = RiskLevel.LOW,
        confirm_fn: Callable[[OperationType, RiskLevel], bool] | None = None,
    ) -> None:
        self._max_auto: RiskLevel = max_auto_approve
        self._confirm_fn = confirm_fn
        self._audit_log: list[SafetyDecision] = []

    def evaluate(
        self,
        operation: OperationType,
        target: str = "",
        context: str = "",
    ) -> SafetyDecision:
        risk = OPERATION_RISK.get(operation, RiskLevel.HIGH)
        risk_val = list(RiskLevel).index(risk)
        auto_val = list(RiskLevel).index(self._max_auto)

        if risk_val <= auto_val:
            decision = SafetyDecision(
                operation=operation,
                risk=risk,
                allowed=True,
                reason="Auto-approved: within safe threshold",
            )
        elif risk == RiskLevel.CRITICAL:
            decision = SafetyDecision(
                operation=operation,
                risk=risk,
                allowed=False,
                reason=f"BLOCKED: {operation.value} is CRITICAL risk. "
                f"Requires explicit authorization. Target: {target}",
                requires_confirmation=True,
            )
        else:
            allowed = False
            if self._confirm_fn:
                allowed = self._confirm_fn(operation, risk)
            decision = SafetyDecision(
                operation=operation,
                risk=risk,
                allowed=allowed,
                reason=(
                    "Confirmed by operator"
                    if allowed
                    else f"Requires confirmation: {operation.value} ({risk.value} risk)"
                ),
                requires_confirmation=not allowed,
            )

        logger.info(
            "SafetyAudit: op=%s risk=%s allowed=%s target=%s",
            operation.value,
            risk.value,
            decision.allowed,
            target,
        )
        self._audit_log.append(decision)
        return decision

    @property
    def audit_log(self) -> list[SafetyDecision]:
        return list(self._audit_log)

    def clear_log(self) -> None:
        self._audit_log.clear()
