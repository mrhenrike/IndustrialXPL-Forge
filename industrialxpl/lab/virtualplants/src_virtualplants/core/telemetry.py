"""JSONL telemetry and ground-truth timeline.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from threading import Lock
from typing import Callable, List, Optional

from ..paths import TMP_DIR, ensure_workspace_dirs
from .events import PlantEvent


LOGGER = logging.getLogger("virtualplants.telemetry")


class TelemetryBus:
    """Thread-safe event bus with optional JSONL persistence."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        """Create bus and workspace-local log file."""
        ensure_workspace_dirs()
        tempfile.tempdir = str(TMP_DIR)
        self._lock = Lock()
        self._events: List[PlantEvent] = []
        self._subscribers: List[Callable[[PlantEvent], None]] = []
        self._log_path = log_path or (TMP_DIR / "virtualplants-events.jsonl")
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def subscribe(self, callback: Callable[[PlantEvent], None]) -> None:
        """Register a detection or UI subscriber."""
        with self._lock:
            self._subscribers.append(callback)

    def emit(self, event: PlantEvent) -> None:
        """Record, persist and fan-out one event."""
        with self._lock:
            self._events.append(event)
            subscribers = list(self._subscribers)
            line = json.dumps(event.as_dict(), sort_keys=True)
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        for callback in subscribers:
            try:
                callback(event)
            except Exception as exc:  # noqa: BLE001 - subscriber isolation
                LOGGER.warning("telemetry subscriber failed: %s", exc)

    def timeline(self) -> List[PlantEvent]:
        """Return a copy of recorded events."""
        with self._lock:
            return list(self._events)

    def ground_truth(self) -> List[dict]:
        """Return serialized timeline for defense scoring."""
        return [item.as_dict() for item in self.timeline()]

    @property
    def log_path(self) -> Path:
        """Path of the JSONL event log."""
        return self._log_path
