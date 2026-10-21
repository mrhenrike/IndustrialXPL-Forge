"""Lab containment: bind policy, target allowlist and resource caps.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional, Sequence


LOGGER = logging.getLogger("virtualplants.safety")

LOOPBACK_NAMES: FrozenSet[str] = frozenset({"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})


class LabSafetyError(ValueError):
    """Raised when a request would leave the authorized lab boundary."""


@dataclass(frozen=True)
class ResourceLimits:
    """Hard caps for lab services and attack runners."""

    max_connections: int = 32
    max_message_bytes: int = 1024
    request_timeout_seconds: float = 5.0
    scenario_timeout_seconds: float = 120.0
    rate_per_second: int = 40
    memory_mb: int = 256
    cpu_seconds: int = 30


def _normalize_host(host: str) -> str:
    """Strip brackets and whitespace from a host literal."""
    value = str(host or "").strip().lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" in value:
        value = value.split("%", 1)[0]
    return value


def resolve_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve host to a single IP address without following redirects."""
    normalized = _normalize_host(host)
    if not normalized or len(normalized) > 253:
        raise LabSafetyError("invalid host")
    try:
        return ipaddress.ip_address(normalized)
    except ValueError:
        pass
    if normalized in LOOPBACK_NAMES:
        return ipaddress.ip_address("127.0.0.1")
    try:
        infos = socket.getaddrinfo(normalized, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise LabSafetyError("unable to resolve host") from exc
    if not infos:
        raise LabSafetyError("unable to resolve host")
    return ipaddress.ip_address(infos[0][4][0])


def is_lab_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for loopback or RFC1918/unique-local addresses."""
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_unspecified
    )


def assert_lab_target(
    host: str,
    allowed_hosts: Optional[Sequence[str]] = None,
) -> str:
    """Reject public or unexpected targets. Returns canonical host string."""
    normalized = _normalize_host(host)
    address = resolve_ip(normalized)
    if address.is_unspecified:
        raise LabSafetyError("wildcard bind is not a valid attack target")
    if not is_lab_ip(address):
        raise LabSafetyError("public or non-lab address is not allowed")
    if allowed_hosts:
        allow = {_normalize_host(item) for item in allowed_hosts}
        resolved_allow: set[str] = set(allow)
        for item in list(allow):
            try:
                resolved_allow.add(str(resolve_ip(item)))
            except LabSafetyError:
                continue
        if normalized not in resolved_allow and str(address) not in resolved_allow:
            raise LabSafetyError("target is not in the scenario allowlist")
    return str(address)


def validate_bind_host(host: str, expose_lan: bool) -> str:
    """Default to loopback. LAN bind requires an explicit flag and private IP."""
    normalized = _normalize_host(host) or "127.0.0.1"
    address = resolve_ip(normalized)
    if not expose_lan:
        if not address.is_loopback:
            raise LabSafetyError("bind host must be loopback unless --expose-lan is set")
        return "127.0.0.1" if address.version == 4 else "::1"
    if address.is_unspecified:
        LOGGER.warning("LAN expose requested with unspecified bind; using 0.0.0.0")
        return "0.0.0.0"
    if not is_lab_ip(address):
        raise LabSafetyError("LAN bind must use a private or loopback address")
    return str(address)


def validate_port(port: int) -> int:
    """Accept only unprivileged lab ports by default, plus documented OT ports."""
    value = int(port)
    if value == 0:
        return 0
    allowed_privileged = {80, 102, 161, 502, 2404, 4840, 44818, 20000, 47808}
    if value <= 0 or value > 65535:
        raise LabSafetyError("invalid TCP/UDP port")
    if value < 1024 and value not in allowed_privileged:
        raise LabSafetyError("privileged port is not allowed")
    return value


def require_confirmation(confirm: bool, action: str) -> None:
    """Block live PoC execution without an explicit confirm flag."""
    if not confirm:
        raise LabSafetyError(
            "refusing to run '%s' without --confirm (authorized isolated lab only)" % action
        )


def clamp_limits(limits: ResourceLimits) -> ResourceLimits:
    """Sanitize resource limits to safe lab ranges."""
    return ResourceLimits(
        max_connections=max(1, min(256, int(limits.max_connections))),
        max_message_bytes=max(64, min(4096, int(limits.max_message_bytes))),
        request_timeout_seconds=max(0.2, min(30.0, float(limits.request_timeout_seconds))),
        scenario_timeout_seconds=max(5.0, min(600.0, float(limits.scenario_timeout_seconds))),
        rate_per_second=max(1, min(200, int(limits.rate_per_second))),
        memory_mb=max(32, min(1024, int(limits.memory_mb))),
        cpu_seconds=max(1, min(120, int(limits.cpu_seconds))),
    )


def iter_safe_argv(argv: Iterable[str]) -> tuple[str, ...]:
    """Return a frozen argv tuple. Callers must not join these into a shell."""
    cleaned: list[str] = []
    for item in argv:
        text = str(item)
        if "\x00" in text or "\n" in text or "\r" in text:
            raise LabSafetyError("control characters are not allowed in process arguments")
        if len(text) > 4096:
            raise LabSafetyError("argument too long")
        cleaned.append(text)
    return tuple(cleaned)
