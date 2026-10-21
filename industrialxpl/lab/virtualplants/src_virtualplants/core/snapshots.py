"""In-memory snapshots for lab rollback.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class Snapshot:
    """Serializable plant or target snapshot."""

    snapshot_id: str
    created_at: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def clone_payload(self) -> Dict[str, Any]:
        """Return a detached copy of snapshot data."""
        return deepcopy(self.payload)


class SnapshotStore:
    """Keep a named snapshot for restore after PoC runs."""

    def __init__(self) -> None:
        """Initialize empty store."""
        self._current: Optional[Snapshot] = None

    def capture(self, snapshot_id: str, payload: Dict[str, Any]) -> Snapshot:
        """Store a deep copy of payload."""
        snap = Snapshot(
            snapshot_id=snapshot_id,
            created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            payload=deepcopy(payload),
        )
        self._current = snap
        return snap

    def restore(self) -> Dict[str, Any]:
        """Return last captured payload or raise."""
        if self._current is None:
            raise RuntimeError("no snapshot available")
        return self._current.clone_payload()

    def has_snapshot(self) -> bool:
        """Return True when a snapshot exists."""
        return self._current is not None

    def dumps(self) -> str:
        """Serialize current snapshot as JSON."""
        if self._current is None:
            return "{}"
        return json.dumps(
            {
                "snapshot_id": self._current.snapshot_id,
                "created_at": self._current.created_at,
                "payload": self._current.payload,
            },
            sort_keys=True,
        )
