"""Structured process and protocol events.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


def utc_now() -> str:
    """Return ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PlantEvent:
    """One auditable lab event."""

    event_type: str
    source: str
    message: str
    severity: str = "info"
    details: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: str = field(default_factory=utc_now)
    scenario_id: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """Serialize event for JSONL telemetry."""
        payload = asdict(self)
        payload["details"] = dict(self.details)
        return payload
