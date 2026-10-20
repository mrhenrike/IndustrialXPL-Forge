"""IEC 62443 compliance engine for OT/ICS security assessment."""


from dataclasses import dataclass, field
from enum import Enum


__all__ = [
    "ComplianceCheck",
    "ComplianceResult",
    "IEC62443Engine",
    "SecurityLevel",
]


class SecurityLevel(Enum):
    SL0 = 0
    SL1 = 1
    SL2 = 2
    SL3 = 3
    SL4 = 4


@dataclass
class ComplianceResult:
    requirement_id: str
    title: str
    passed: bool
    security_level: SecurityLevel
    evidence: str = ""
    remediation: str = ""


@dataclass
class ComplianceCheck:
    requirement_id: str
    title: str
    description: str
    security_level: SecurityLevel
    category: str = ""
    check_fn: str | None = None


class IEC62443Engine:
    """Evaluate OT/ICS targets against IEC 62443 requirements.

    Checks are organized by security level (SL1-SL4) and can be
    extended with custom requirement definitions.
    """

    def __init__(self) -> None:
        self._checks: dict[str, ComplianceCheck] = {}
        self._results: list[ComplianceResult] = []
        self._load_baseline()

    def _load_baseline(self) -> None:
        baseline = [
            ComplianceCheck(
                requirement_id="SR 1.1",
                title="Human user identification and authentication",
                description="Identify and authenticate all human users",
                security_level=SecurityLevel.SL1,
                category="FR1-IAC",
            ),
            ComplianceCheck(
                requirement_id="SR 1.2",
                title="Software process and device identification",
                description="Identify and authenticate software processes and devices",
                security_level=SecurityLevel.SL1,
                category="FR1-IAC",
            ),
            ComplianceCheck(
                requirement_id="SR 1.3",
                title="Account management",
                description="Manage all accounts by authorized users",
                security_level=SecurityLevel.SL1,
                category="FR1-IAC",
            ),
            ComplianceCheck(
                requirement_id="SR 2.1",
                title="Authorization enforcement",
                description="Enforce assigned privileges for all actions",
                security_level=SecurityLevel.SL1,
                category="FR2-UC",
            ),
            ComplianceCheck(
                requirement_id="SR 3.1",
                title="Communication integrity",
                description="Protect integrity of transmitted information",
                security_level=SecurityLevel.SL1,
                category="FR3-SI",
            ),
            ComplianceCheck(
                requirement_id="SR 3.3",
                title="Security functionality verification",
                description="Verify intended operation of security functions",
                security_level=SecurityLevel.SL2,
                category="FR3-SI",
            ),
            ComplianceCheck(
                requirement_id="SR 4.1",
                title="Information confidentiality",
                description="Protect confidentiality of information at rest and transit",
                security_level=SecurityLevel.SL2,
                category="FR4-DC",
            ),
            ComplianceCheck(
                requirement_id="SR 5.1",
                title="Network segmentation",
                description="Segment control system networks from non-control networks",
                security_level=SecurityLevel.SL1,
                category="FR5-RDF",
            ),
            ComplianceCheck(
                requirement_id="SR 6.1",
                title="Audit log accessibility",
                description="Provide audit logs to authorized personnel",
                security_level=SecurityLevel.SL1,
                category="FR6-TRE",
            ),
            ComplianceCheck(
                requirement_id="SR 7.1",
                title="Denial of service protection",
                description="Operate in degraded mode during DoS events",
                security_level=SecurityLevel.SL1,
                category="FR7-RA",
            ),
            ComplianceCheck(
                requirement_id="SR 7.6",
                title="Network and security configuration settings",
                description="Provide ability to configure network and security settings",
                security_level=SecurityLevel.SL2,
                category="FR7-RA",
            ),
        ]
        for check in baseline:
            self._checks[check.requirement_id] = check

    @property
    def checks(self) -> dict[str, ComplianceCheck]:
        return dict(self._checks)

    def add_check(self, check: ComplianceCheck) -> None:
        self._checks[check.requirement_id] = check

    def evaluate(
        self,
        requirement_id: str,
        passed: bool,
        evidence: str = "",
        remediation: str = "",
    ) -> ComplianceResult:
        if requirement_id not in self._checks:
            raise KeyError(f"Unknown requirement: {requirement_id}")
        check = self._checks[requirement_id]
        result = ComplianceResult(
            requirement_id=requirement_id,
            title=check.title,
            passed=passed,
            security_level=check.security_level,
            evidence=evidence,
            remediation=remediation,
        )
        self._results.append(result)
        return result

    def results(self) -> list[ComplianceResult]:
        return list(self._results)

    def results_by_level(self, level: SecurityLevel) -> list[ComplianceResult]:
        return [r for r in self._results if r.security_level == level]

    def compliance_score(self) -> float:
        if not self._results:
            return 0.0
        passed = sum(1 for r in self._results if r.passed)
        return (passed / len(self._results)) * 100.0

    def gaps(self) -> list[ComplianceResult]:
        return [r for r in self._results if not r.passed]

    def reset(self) -> None:
        self._results.clear()
