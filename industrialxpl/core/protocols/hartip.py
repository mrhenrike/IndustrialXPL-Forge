"""HART-IP protocol stub.

HART (Highway Addressable Remote Transducer) over IP for field
instrument communication. Supports commands 0-3 (universal) and
device-specific commands.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

HART_IP_PORT = 5094
HART_VERSION = 7


class HartCommand:
    READ_UNIQUE_ID = 0
    READ_PRIMARY_VAR = 1
    READ_LOOP_CURRENT = 2
    READ_DYNAMIC_VARS = 3
    WRITE_POLLING_ADDRESS = 6
    READ_LOOP_CONFIG = 7
    READ_DEVICE_VAR = 9
    READ_UNIQUE_ID_TAG = 11
    READ_MESSAGE = 12
    READ_TAG_DESC_DATE = 13
    READ_PRIMARY_VAR_INFO = 14
    READ_OUTPUT_INFO = 15
    WRITE_PRIMARY_VAR_UNIT = 44
    WRITE_DEVICE_RESET = 42


@dataclass
class HartDevice:
    tag: str = ""
    unique_id: bytes = b""
    manufacturer_id: int = 0
    device_type: int = 0
    device_revision: int = 0
    software_revision: int = 0
    hardware_revision: int = 0


@dataclass
class ProcessVariable:
    name: str
    value: float = 0.0
    unit: str = ""
    status: str = "good"


class HartIpClient:
    """Skeleton HART-IP client for field instrument communication."""

    def __init__(self, host: str, port: int = HART_IP_PORT) -> None:
        self.host = host
        self.port = port
        self._connected = False
        self._transaction_id: int = 0

    def connect(self) -> bool:
        logger.info("HART-IP connect to %s:%d", self.host, self.port)
        raise NotImplementedError("HART-IP TCP/UDP transport required")

    def disconnect(self) -> None:
        self._connected = False

    def send_command(self, command: int, data: bytes = b"") -> bytes:
        raise NotImplementedError("HART-IP command framing not implemented")

    def read_unique_id(self) -> HartDevice:
        raise NotImplementedError("Command 0 not implemented")

    def read_primary_variable(self) -> ProcessVariable:
        raise NotImplementedError("Command 1 not implemented")

    def read_loop_current(self) -> float:
        raise NotImplementedError("Command 2 not implemented")

    def read_dynamic_variables(self) -> List[ProcessVariable]:
        raise NotImplementedError("Command 3 not implemented")

    def read_device_variable(self, slot: int) -> ProcessVariable:
        raise NotImplementedError("Command 9 not implemented")


def build_hart_ip_header(
    msg_type: int, command: int, data: bytes = b""
) -> bytes:
    """Build a HART-IP message header (version 1)."""
    version = 1
    status = 0
    sequence = 0
    byte_count = 8 + len(data)
    header = struct.pack(
        ">BBHHBB",
        version,
        msg_type,
        sequence,
        byte_count,
        status,
        command,
    )
    return header + data
