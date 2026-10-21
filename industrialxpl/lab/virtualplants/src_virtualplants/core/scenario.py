"""Strict scenario manifest loader.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..paths import SCENARIOS_DIR
from .devices import DeviceRole, DeviceSpec
from .safety import ResourceLimits, clamp_limits, validate_bind_host, validate_port


ALLOWED_PROFILES = frozenset({"vulnerable", "patched", "lab"})
ALLOWED_REPRODUCTION = frozenset({"process", "protocol", "binary"})
ALLOWED_PROTOCOLS = frozenset(
    {
        "modbus-tcp",
        "opcua",
        "http",
        "s7comm",
        "enip-cip",
        "dnp3",
        "iec60870-5-104",
        "iec61850",
        "bacnet",
        "profinet",
        "pjl",
    }
)
ALLOWED_KEYS = frozenset(
    {
        "id",
        "version",
        "title",
        "plant",
        "profile",
        "bind_host",
        "expose_lan",
        "devices",
        "protocols",
        "endpoints",
        "allowed_targets",
        "allowed_attacks",
        "resource_limits",
        "timeout_seconds",
        "reproduction",
        "rollback",
        "notes",
    }
)
ALLOWED_ENDPOINT_KEYS = frozenset({"name", "protocol", "port", "path", "security_profile"})
ALLOWED_LIMIT_KEYS = frozenset(
    {
        "max_connections",
        "max_message_bytes",
        "request_timeout_seconds",
        "scenario_timeout_seconds",
        "rate_per_second",
        "memory_mb",
        "cpu_seconds",
    }
)


class ManifestError(ValueError):
    """Invalid scenario document."""


@dataclass(frozen=True)
class EndpointSpec:
    """Network endpoint published by a scenario."""

    name: str
    protocol: str
    port: int
    path: str = ""
    security_profile: str = "insecure"


@dataclass(frozen=True)
class ScenarioManifest:
    """Validated lab scenario."""

    scenario_id: str
    version: str
    title: str
    plant: str
    profile: str
    bind_host: str
    expose_lan: bool
    devices: List[DeviceSpec]
    protocols: List[str]
    endpoints: List[EndpointSpec]
    allowed_targets: List[str]
    allowed_attacks: List[str]
    resource_limits: ResourceLimits
    timeout_seconds: float
    reproduction: str
    rollback: str
    notes: str = ""
    source_path: Optional[Path] = None


def _require(data: Dict[str, Any], key: str, expected: Union[type, tuple]) -> Any:
    """Read a required field with type check."""
    if key not in data:
        raise ManifestError("missing field: %s" % key)
    value = data[key]
    if not isinstance(value, expected):
        raise ManifestError("field %s has invalid type" % key)
    return value


def _reject_unknown(data: Dict[str, Any], allowed: frozenset, context: str) -> None:
    """Deny extra JSON keys."""
    unexpected = set(data) - set(allowed)
    if unexpected:
        raise ManifestError("unexpected keys in %s: %s" % (context, ", ".join(sorted(unexpected))))


def parse_manifest(data: Dict[str, Any], source_path: Optional[Path] = None) -> ScenarioManifest:
    """Validate a scenario mapping."""
    _reject_unknown(data, ALLOWED_KEYS, "scenario")
    scenario_id = str(_require(data, "id", str)).strip()
    if not scenario_id or len(scenario_id) > 80:
        raise ManifestError("invalid scenario id")
    profile = str(_require(data, "profile", str))
    if profile not in ALLOWED_PROFILES:
        raise ManifestError("invalid profile")
    reproduction = str(_require(data, "reproduction", str))
    if reproduction not in ALLOWED_REPRODUCTION:
        raise ManifestError("invalid reproduction mode")
    expose_lan = bool(data.get("expose_lan", False))
    bind_host = validate_bind_host(str(data.get("bind_host") or "127.0.0.1"), expose_lan)
    protocols = list(_require(data, "protocols", list))
    for proto in protocols:
        if proto not in ALLOWED_PROTOCOLS:
            raise ManifestError("unsupported protocol: %s" % proto)
    devices: List[DeviceSpec] = []
    for item in _require(data, "devices", list):
        if not isinstance(item, dict):
            raise ManifestError("device entries must be objects")
        role = DeviceRole(str(item.get("role")))
        device = DeviceSpec(
            device_id=str(item.get("device_id") or ""),
            role=role,
            vendor=str(item.get("vendor") or "generic"),
            model=str(item.get("model") or "lab"),
            firmware=str(item.get("firmware") or "virtual"),
            protocols=list(item.get("protocols") or []),
            tags=dict(item.get("tags") or {}),
            notes=item.get("notes"),
        )
        if not device.device_id:
            raise ManifestError("device_id is required")
        devices.append(device)
    endpoints: List[EndpointSpec] = []
    for item in _require(data, "endpoints", list):
        if not isinstance(item, dict):
            raise ManifestError("endpoint entries must be objects")
        _reject_unknown(item, ALLOWED_ENDPOINT_KEYS, "endpoint")
        endpoints.append(
            EndpointSpec(
                name=str(_require(item, "name", str)),
                protocol=str(_require(item, "protocol", str)),
                port=validate_port(int(_require(item, "port", int))),
                path=str(item.get("path") or ""),
                security_profile=str(item.get("security_profile") or "insecure"),
            )
        )
    limits_raw = data.get("resource_limits") or {}
    if not isinstance(limits_raw, dict):
        raise ManifestError("resource_limits must be an object")
    _reject_unknown(limits_raw, ALLOWED_LIMIT_KEYS, "resource_limits")
    limits = clamp_limits(
        ResourceLimits(
            max_connections=int(limits_raw.get("max_connections", 32)),
            max_message_bytes=int(limits_raw.get("max_message_bytes", 1024)),
            request_timeout_seconds=float(limits_raw.get("request_timeout_seconds", 5.0)),
            scenario_timeout_seconds=float(limits_raw.get("scenario_timeout_seconds", 120.0)),
            rate_per_second=int(limits_raw.get("rate_per_second", 40)),
            memory_mb=int(limits_raw.get("memory_mb", 256)),
            cpu_seconds=int(limits_raw.get("cpu_seconds", 30)),
        )
    )
    allowed_targets = [str(item) for item in _require(data, "allowed_targets", list)]
    if not allowed_targets:
        raise ManifestError("allowed_targets cannot be empty")
    timeout = float(_require(data, "timeout_seconds", (int, float)))
    return ScenarioManifest(
        scenario_id=scenario_id,
        version=str(_require(data, "version", str)),
        title=str(_require(data, "title", str)),
        plant=str(_require(data, "plant", str)),
        profile=profile,
        bind_host=bind_host,
        expose_lan=expose_lan,
        devices=devices,
        protocols=protocols,
        endpoints=endpoints,
        allowed_targets=allowed_targets,
        allowed_attacks=[str(item) for item in _require(data, "allowed_attacks", list)],
        resource_limits=limits,
        timeout_seconds=max(5.0, min(600.0, timeout)),
        reproduction=reproduction,
        rollback=str(data.get("rollback") or "snapshot"),
        notes=str(data.get("notes") or ""),
        source_path=source_path,
    )


def load_manifest(path: Path) -> ScenarioManifest:
    """Load and validate a scenario JSON file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError("scenario root must be an object")
    return parse_manifest(raw, source_path=path)


def list_manifests(root: Optional[Path] = None) -> List[ScenarioManifest]:
    """Load every scenario.json under the scenarios tree."""
    base = root or SCENARIOS_DIR
    found: List[ScenarioManifest] = []
    if not base.exists():
        return found
    for path in sorted(base.glob("*/scenario.json")):
        found.append(load_manifest(path))
    return found


def get_manifest(scenario_id: str, root: Optional[Path] = None) -> ScenarioManifest:
    """Find a scenario by id."""
    for manifest in list_manifests(root):
        if manifest.scenario_id == scenario_id:
            return manifest
    raise ManifestError("unknown scenario: %s" % scenario_id)
