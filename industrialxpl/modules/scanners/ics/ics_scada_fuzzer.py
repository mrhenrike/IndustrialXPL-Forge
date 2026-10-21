"""Wrapper stub for ICS SCADA Fuzzer.

Source: https://github.com/ridpath/ics-scada-fuzzer
License: verify
SRC-ID: SRC-992
Category: ICS fuzzing, Modbus/DNP3/S7comm/IEC104/OPC-UA

Protocol-aware fuzzer for industrial control systems. Supports
Modbus TCP, DNP3, S7comm, IEC 60870-5-104, and OPC-UA with
mutation and generation strategies.
"""

from dataclasses import dataclass


@dataclass
class ICSFuzzerConfig:
    target: str = ""
    port: int = 502
    protocol: str = "modbus"
    strategy: str = "mutation"  # mutation, generation
    iterations: int = 1000
    timeout: int = 5
