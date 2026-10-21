"""Process and protocol tag map.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


ALLOWED_AREAS = frozenset({"coil", "discrete_input", "input_register", "holding_register", "opcua", "http"})


@dataclass(frozen=True)
class TagSpec:
    """Named process point mapped to a protocol address."""

    name: str
    area: str
    address: int
    writable: bool
    description: str
    scale_min: Optional[float] = None
    scale_max: Optional[float] = None

    def validate(self) -> None:
        """Reject unexpected area or negative addresses."""
        if self.area not in ALLOWED_AREAS:
            raise ValueError("unsupported tag area: %s" % self.area)
        if int(self.address) < 0 or int(self.address) > 65535:
            raise ValueError("tag address out of range")
        if not self.name or len(self.name) > 64:
            raise ValueError("invalid tag name")


def index_tags(tags: Dict[str, TagSpec]) -> Dict[str, TagSpec]:
    """Return a copy after validating each tag."""
    indexed: Dict[str, TagSpec] = {}
    for name, spec in tags.items():
        spec.validate()
        indexed[name] = spec
    return indexed
