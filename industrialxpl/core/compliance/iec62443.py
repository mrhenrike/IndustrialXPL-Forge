"""IEC 62443 specific requirement definitions and helpers.

Foundational requirements (FR1-FR7) mapped to system requirements (SR)
with security level targets.
"""

from __future__ import annotations

from typing import Dict, List

from . import ComplianceCheck, SecurityLevel

FOUNDATIONAL_REQUIREMENTS: Dict[str, str] = {
    "FR1": "Identification and Authentication Control (IAC)",
    "FR2": "Use Control (UC)",
    "FR3": "System Integrity (SI)",
    "FR4": "Data Confidentiality (DC)",
    "FR5": "Restricted Data Flow (RDF)",
    "FR6": "Timely Response to Events (TRE)",
    "FR7": "Resource Availability (RA)",
}

ZONE_CONDUIT_TYPES: List[str] = [
    "enterprise",
    "manufacturing",
    "supervisory",
    "basic_control",
    "process",
    "safety",
    "dmz",
]


def checks_for_level(
    checks: Dict[str, ComplianceCheck], target: SecurityLevel
) -> List[ComplianceCheck]:
    """Filter checks applicable up to a given security level target."""
    return [c for c in checks.values() if c.security_level.value <= target.value]


def checks_by_category(
    checks: Dict[str, ComplianceCheck], category_prefix: str
) -> List[ComplianceCheck]:
    """Return checks whose category starts with *category_prefix* (e.g. 'FR1')."""
    return [c for c in checks.values() if c.category.startswith(category_prefix)]


def zone_security_level(zone_type: str) -> SecurityLevel:
    """Suggest a minimum security level for a Purdue-model zone type."""
    mapping = {
        "enterprise": SecurityLevel.SL1,
        "manufacturing": SecurityLevel.SL2,
        "supervisory": SecurityLevel.SL2,
        "basic_control": SecurityLevel.SL3,
        "process": SecurityLevel.SL3,
        "safety": SecurityLevel.SL4,
        "dmz": SecurityLevel.SL2,
    }
    return mapping.get(zone_type, SecurityLevel.SL1)
