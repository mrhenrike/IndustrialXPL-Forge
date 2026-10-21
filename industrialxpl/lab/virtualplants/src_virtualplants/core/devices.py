"""OT device role contracts used by scenario manifests.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class DeviceRole(str, Enum):
    """Supported OT device personas."""

    PLC = "plc"
    RTU = "rtu"
    IED = "ied"
    GATEWAY = "gateway"
    SCADA = "scada"
    HMI = "hmi"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    PRINTER = "printer"
    ROUTER = "router"


@dataclass(frozen=True)
class DeviceSpec:
    """Connectable lab device description."""

    device_id: str
    role: DeviceRole
    vendor: str
    model: str
    firmware: str
    protocols: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    notes: Optional[str] = None
