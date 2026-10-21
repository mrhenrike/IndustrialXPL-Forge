"""Detection rules for attack/defense lab scoring.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

from .events import PlantEvent, utc_now
from .telemetry import TelemetryBus


def _parse_ts(value: str) -> datetime:
    """Parse ISO timestamps produced by PlantEvent."""
    text = value.replace("Z", "+00:00")
    return datetime.fromisoformat(text)


class DetectionEngine:
    """Correlate protocol and process events into detections."""

    def __init__(self, bus: TelemetryBus) -> None:
        """Attach to a telemetry bus."""
        self._bus = bus
        self._detections: List[PlantEvent] = []
        self._reset_times: Deque[datetime] = deque(maxlen=32)
        self._last_speed: Optional[int] = None
        bus.subscribe(self.observe)

    def observe(self, event: PlantEvent) -> None:
        """Inspect an incoming event and maybe raise a detection."""
        details = event.details
        event_type = event.event_type
        if event_type == "detection":
            return
        if event_type == "modbus_write":
            self._on_modbus_write(event, details)
        elif event_type == "opcua_browse":
            self._raise("opcua_enumeration", event, "Anonymous OPC UA namespace browse")
        elif event_type == "http_path_bypass":
            self._raise("path_normalization", event, "HTTP path normalization bypass observed")
        elif event_type == "protocol_crash":
            self._raise("protocol_crash", event, "Protocol service crashed or reset")
        elif event_type == "process_alert":
            message = str(details.get("alert") or event.message)
            if "TAMPERING" in message.upper() or "OVERSPEED" in message.upper():
                self._raise("process_tampering", event, message)

    def _on_modbus_write(self, event: PlantEvent, details: Dict[str, object]) -> None:
        """Evaluate holding-register and coil writes."""
        area = str(details.get("area") or "")
        address = int(details.get("address") or 0)
        value = int(details.get("value") or 0)
        if area == "holding_register":
            if address == 7 and value > 700:
                self._raise("overspeed", event, "Conveyor speed setpoint above lab threshold")
            if address in (2, 3) and value == 0:
                self._raise("sensor_blackout", event, "Process sensor disabled via Modbus")
            if address == 1 and value == 1:
                now = _parse_ts(event.timestamp)
                self._reset_times.append(now)
                recent = [item for item in self._reset_times if (now - item).total_seconds() <= 5]
                if len(recent) >= 3:
                    self._raise("reset_storm", event, "Repeated reset pulses within 5 seconds")
            if value < 0 or value > 65535:
                self._raise("out_of_range_write", event, "Register value out of uint16 range")
            self._last_speed = value if address == 7 else self._last_speed
        elif area == "coil":
            if address in (0, 2, 3, 4, 5):
                self._raise("coil_tamper", event, "Process coil write on command/sensor map")

    def _raise(self, name: str, source_event: PlantEvent, message: str) -> None:
        """Emit a detection event once per burst when possible."""
        detection = PlantEvent(
            event_type="detection",
            source="detection-engine",
            message=message,
            severity="warning",
            scenario_id=source_event.scenario_id,
            details={
                "rule": name,
                "cause_event_id": source_event.event_id,
                "cause_type": source_event.event_type,
            },
            timestamp=utc_now(),
        )
        self._detections.append(detection)
        self._bus.emit(detection)

    def findings(self) -> List[PlantEvent]:
        """Return detections raised so far."""
        return list(self._detections)

    def ruleset(self) -> Tuple[str, ...]:
        """Documented detection names."""
        return (
            "overspeed",
            "sensor_blackout",
            "reset_storm",
            "out_of_range_write",
            "coil_tamper",
            "opcua_enumeration",
            "path_normalization",
            "protocol_crash",
            "process_tampering",
        )
