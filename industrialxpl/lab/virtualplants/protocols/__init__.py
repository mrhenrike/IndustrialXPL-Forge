"""Protocol adapter contracts.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class ProtocolContract:
    """Declared OT protocol surface for future adapters."""

    name: str
    default_port: int
    transport: str
    status: str
    notes: str


PROTOCOL_CONTRACTS = (
    ProtocolContract("modbus-tcp", 502, "tcp", "implemented", "FC 1/2/3/4/5/6/15/16/43"),
    ProtocolContract("opcua", 4840, "tcp", "implemented", "profiles insecure/authenticated/sign-encrypt"),
    ProtocolContract("http", 8080, "tcp", "implemented", "HMI and FUXA lab emulator"),
    ProtocolContract("s7comm", 102, "tcp", "contract", "Siemens S7comm/RFC1006 adapter planned"),
    ProtocolContract("enip-cip", 44818, "tcp", "contract", "EtherNet/IP CIP adapter planned"),
    ProtocolContract("dnp3", 20000, "tcp", "contract", "DNP3 outstation adapter planned"),
    ProtocolContract("iec60870-5-104", 2404, "tcp", "emulated", "Parser crash class for lab pairing"),
    ProtocolContract("iec61850", 102, "tcp", "emulated", "MMS/GOOSE malformed-frame pairing"),
    ProtocolContract("bacnet", 47808, "udp", "contract", "BACnet/IP adapter planned"),
    ProtocolContract("profinet", 34964, "udp", "contract", "PROFINET DCP adapter planned"),
    ProtocolContract("pjl", 9100, "tcp", "contract", "Printer persona only, via PrinterXPL-Forge"),
)


class LabService(Protocol):
    """Startable lab network service."""

    async def start(self) -> None:
        """Bind and serve."""

    async def stop(self) -> None:
        """Release sockets."""
