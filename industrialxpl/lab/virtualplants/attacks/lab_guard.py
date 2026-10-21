"""Standalone target guard for attack scripts that run without PYTHONPATH.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import ipaddress
import socket


class LabTargetError(ValueError):
    """Raised when a script is aimed outside the local lab."""


def assert_lab_target(host: str) -> str:
    """Allow only loopback or RFC1918/unique-local destinations."""
    value = str(host or "").strip().lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        raise LabTargetError("empty host")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if value in {"localhost"}:
            address = ipaddress.ip_address("127.0.0.1")
        else:
            try:
                infos = socket.getaddrinfo(value, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                raise LabTargetError("unable to resolve host") from exc
            address = ipaddress.ip_address(infos[0][4][0])
    if address.is_unspecified or not (address.is_loopback or address.is_private or address.is_link_local):
        raise LabTargetError("refusing non-lab target %s" % host)
    return str(address)
