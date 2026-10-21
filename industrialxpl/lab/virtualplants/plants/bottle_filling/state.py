"""Shared state model for bottle-filling process.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from threading import Lock
from typing import Dict, List, Optional


@dataclass
class BottleProcessState:
    """State fields exposed to web and OT protocols."""

    run_command: bool = True
    bottle_in_position: bool = False
    level_hit: bool = False
    motor_on: bool = True
    nozzle_open: bool = False
    produced_count: int = 0
    spill_count: int = 0
    current_bottle_x: Optional[float] = 0.02
    current_fill_level: float = 0.0
    nozzle_position: float = 0.52
    queue_preview: List[float] = field(default_factory=list)
    bottles: List[Dict[str, object]] = field(default_factory=list)
    sensor_min_position: float = 0.515
    sensor_max_position: float = 0.525
    fill_level_limit: float = 0.92
    bottle_spacing: float = 0.095
    sensor_window: float = 0.02
    level_sensor_enabled: bool = True
    bottle_sensor_enabled: bool = True
    conveyor_speed: float = 0.040
    sabotage_mode: bool = False
    jam_conveyor: bool = False
    free_flow_enabled: bool = False
    collisions_count: int = 0
    broken_count: int = 0
    fallen_count: int = 0
    alerts: List[str] = field(default_factory=list)
    status: str = "RUNNING"
    reset_request: bool = False


class SharedPlantState:
    """Thread-safe access wrapper for process state."""

    def __init__(self) -> None:
        """Initialize lock and default state."""
        self._lock = Lock()
        self._state = BottleProcessState()

    def get(self) -> BottleProcessState:
        """Return a copy of current process state."""
        with self._lock:
            data = asdict(self._state)
        return BottleProcessState(**data)

    def patch(self, **kwargs: object) -> None:
        """Update a subset of fields in a thread-safe way."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._state, key):
                    setattr(self._state, key, value)

    def set_run(self, enabled: bool) -> None:
        """Set run command and textual status."""
        with self._lock:
            self._state.run_command = enabled
            self._state.status = "RUNNING" if enabled else "STOPPED"

    def request_reset(self) -> None:
        """Signal reset request to simulation loop."""
        with self._lock:
            self._state.reset_request = True

    def consume_reset_request(self) -> bool:
        """Read and clear reset request flag."""
        with self._lock:
            requested = self._state.reset_request
            self._state.reset_request = False
            return requested

    def as_dict(self) -> Dict[str, object]:
        """Return state dict for JSON serialization."""
        return asdict(self.get())
