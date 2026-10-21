"""Wrapper stub for ICS Ninja Scanner.

Source: https://github.com/MottaSec/ICS-Ninja-Scanner
License: verify
SRC-ID: SRC-655
Category: ICS scanner, multi-protocol, Python

ICS Ninja Scanner scans industrial networks for exposed control
systems across multiple protocols (Modbus, S7comm, DNP3, BACnet,
EtherNet/IP).
"""

from dataclasses import dataclass


@dataclass
class ICSNinjaScannerConfig:
    targets: str = ""
    protocols: list[str] | None = None
    port_range: str = "102,502,20000,47808,44818"
    timeout: int = 5
    threads: int = 10
