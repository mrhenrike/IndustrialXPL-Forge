"""
industrialxpl/protocols/modbus_tcp.py - Native Modbus/TCP protocol stack.

Pure-Python implementation of the Modbus Application Protocol (V1.1b3)
over TCP. No Scapy, no external framework required.

Implements:
    - MBAP header construction and parsing
    - Function codes FC01-FC17, FC20-FC23, FC43 (Read Device ID)
    - Exception response detection and decoding
    - ModbusTcpClient for direct socket communication

Reference:
    Modbus Application Protocol Specification V1.1b3
    MITRE ATT&CK ICS: T0836 Modify Parameter, T0831 Manipulation of View,
                       T0846 Remote System Discovery

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Function code registry
# ---------------------------------------------------------------------------

FC_NAMES: Dict[int, str] = {
    0x01: "ReadCoils",
    0x02: "ReadDiscreteInputs",
    0x03: "ReadHoldingRegisters",
    0x04: "ReadInputRegisters",
    0x05: "WriteSingleCoil",
    0x06: "WriteRegister",
    0x07: "ReadExceptionStatus",
    0x08: "Diagnostics",
    0x0B: "GetCommEventCounter",
    0x0C: "GetCommEventLog",
    0x0F: "WriteMultipleCoils",
    0x10: "WriteMultipleRegisters",
    0x11: "ReportServerId",
    0x14: "ReadFileRecord",
    0x15: "WriteFileRecord",
    0x16: "MaskWriteRegister",
    0x17: "ReadWriteMultipleRegisters",
    0x18: "ReadFIFOQueue",
    0x2B: "ReadDeviceIdentification",
}

EXCEPTION_CODES: Dict[int, str] = {
    0x01: "IllegalFunction",
    0x02: "IllegalDataAddress",
    0x03: "IllegalDataValue",
    0x04: "ServerDeviceFailure",
    0x05: "Acknowledge",
    0x06: "ServerDeviceBusy",
    0x08: "MemoryParityError",
    0x0A: "GatewayPathUnavailable",
    0x0B: "GatewayTargetDeviceFailedToRespond",
}

# Risk classification per FC
FC_RISK: Dict[int, str] = {
    0x01: "READ",   0x02: "READ",   0x03: "READ",   0x04: "READ",
    0x05: "WRITE",  0x06: "WRITE",  0x0F: "WRITE",  0x10: "WRITE",
    0x16: "WRITE",  0x17: "READWRITE",
    0x07: "READ",   0x08: "DIAG",   0x0B: "DIAG",   0x0C: "DIAG",
    0x11: "DIAG",   0x14: "DIAG",   0x15: "WRITE",
    0x2B: "INFO",
}

# Default Modbus TCP port
MODBUS_TCP_PORT = 502


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MbapHeader:
    """Modbus Application Protocol header (7 bytes)."""

    transaction_id: int = 0
    protocol_id: int = 0       # always 0x0000 for Modbus
    length: int = 0            # PDU length + 1 (unit_id)
    unit_id: int = 1


@dataclass
class ModbusFrame:
    """Complete Modbus/TCP frame (MBAP + PDU)."""

    mbap: MbapHeader
    function_code: int
    data: bytes = field(default_factory=bytes)
    is_exception: bool = False
    exception_code: int = 0


@dataclass
class ModbusResponse:
    """Parsed response from a Modbus request."""

    success: bool
    function_code: int
    fc_name: str
    is_exception: bool = False
    exception_code: int = 0
    exception_name: str = ""
    raw_data: bytes = field(default_factory=bytes)
    values: List[int] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

class ModbusTcpFrameBuilder:
    """Builds raw Modbus/TCP frames without Scapy dependency.

    All methods return bytes ready to be sent over a TCP socket.

    Example:
        builder = ModbusTcpFrameBuilder(unit_id=1)
        frame = builder.build_request(fc=0x03, start=0, count=10)
        # Sends FC03 Read Holding Registers, address 0, 10 registers
    """

    def __init__(self, unit_id: int = 1, transaction_id: int = 0x1821) -> None:
        self.unit_id = unit_id
        self._tid = transaction_id

    def _next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def _build_mbap(self, pdu: bytes) -> bytes:
        """Build 7-byte MBAP header prepended to PDU."""
        tid = self._next_tid()
        length = len(pdu) + 1  # PDU + unit_id
        return struct.pack(">HHHB", tid, 0, length, self.unit_id) + pdu

    def build_request(
        self,
        fc: int,
        start: int = 0,
        count: int = 1,
        value: int = 0,
        values: Optional[List[int]] = None,
    ) -> bytes:
        """Build a standard Modbus request frame.

        Args:
            fc: Function code (0x01-0x2B).
            start: Starting address / reference number.
            count: Quantity of coils/registers to read/write.
            value: Single value for FC05/FC06.
            values: List of values for FC0F/FC10.

        Returns:
            Raw bytes of complete Modbus/TCP frame.
        """
        if fc in (0x01, 0x02, 0x03, 0x04):
            # Read FCs: FC | start(2) | count(2)
            pdu = struct.pack(">BHH", fc, start, count)

        elif fc == 0x05:
            # Write Single Coil: value is 0xFF00 (ON) or 0x0000 (OFF)
            coil_val = 0xFF00 if value else 0x0000
            pdu = struct.pack(">BHH", fc, start, coil_val)

        elif fc == 0x06:
            # Write Single Register
            pdu = struct.pack(">BHH", fc, start, value & 0xFFFF)

        elif fc == 0x07:
            # Read Exception Status (no data)
            pdu = struct.pack(">B", fc)

        elif fc == 0x08:
            # Diagnostics sub-function 0x00: Return Query Data
            pdu = struct.pack(">BHH", fc, 0x0000, value & 0xFFFF)

        elif fc == 0x0B:
            # Get Comm Event Counter (no data)
            pdu = struct.pack(">B", fc)

        elif fc == 0x0F:
            # Write Multiple Coils
            coil_list = values or [0] * count
            byte_count = (len(coil_list) + 7) // 8
            coil_bytes = bytearray(byte_count)
            for i, v in enumerate(coil_list):
                if v:
                    coil_bytes[i // 8] |= (1 << (i % 8))
            pdu = (
                struct.pack(">BHH", fc, start, len(coil_list))
                + struct.pack(">B", byte_count)
                + bytes(coil_bytes)
            )

        elif fc == 0x10:
            # Write Multiple Registers
            reg_list = values or [value] * count
            byte_count = len(reg_list) * 2
            reg_bytes = b"".join(struct.pack(">H", v & 0xFFFF) for v in reg_list)
            pdu = (
                struct.pack(">BHH", fc, start, len(reg_list))
                + struct.pack(">B", byte_count)
                + reg_bytes
            )

        elif fc == 0x11:
            # Report Server ID (no data)
            pdu = struct.pack(">B", fc)

        elif fc == 0x16:
            # Mask Write Register: start=ref_num, value=and_mask, count=or_mask
            pdu = struct.pack(">BHH", 0x16, start, value)
            # Append OR mask if provided
            if values and len(values) >= 1:
                pdu += struct.pack(">H", values[0] & 0xFFFF)
            else:
                pdu += struct.pack(">H", 0x0000)

        elif fc == 0x2B:
            # Read Device Identification MEI (sub-fc 0x0E, category 0x01)
            pdu = struct.pack(">BBBB", fc, 0x0E, 0x01, 0x00)

        else:
            # Generic: just FC + start + count
            pdu = struct.pack(">BHH", fc, start, count)

        return self._build_mbap(pdu)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

class ModbusTcpParser:
    """Parses raw Modbus/TCP response bytes.

    Returns structured ModbusResponse objects.
    """

    @staticmethod
    def parse(raw: bytes, expected_fc: int = 0) -> ModbusResponse:
        """Parse a raw Modbus/TCP response.

        Args:
            raw: Raw bytes received from socket.
            expected_fc: Expected function code (for validation).

        Returns:
            ModbusResponse with success/error state and decoded values.
        """
        if not raw or len(raw) < 8:
            return ModbusResponse(
                success=False,
                function_code=expected_fc,
                fc_name=FC_NAMES.get(expected_fc, f"FC{expected_fc:02X}"),
                error="Response too short or empty",
            )

        # MBAP: transaction(2) protocol(2) length(2) unit_id(1)
        tid, proto, length, unit_id = struct.unpack_from(">HHHB", raw, 0)
        fc_raw = raw[7] if len(raw) > 7 else 0
        pdu_data = raw[8:] if len(raw) > 8 else b""

        is_exception = bool(fc_raw & 0x80)
        actual_fc = fc_raw & 0x7F

        if is_exception:
            exc_code = pdu_data[0] if pdu_data else 0
            return ModbusResponse(
                success=False,
                function_code=actual_fc,
                fc_name=FC_NAMES.get(actual_fc, f"FC{actual_fc:02X}"),
                is_exception=True,
                exception_code=exc_code,
                exception_name=EXCEPTION_CODES.get(exc_code, f"Unknown(0x{exc_code:02X})"),
                raw_data=pdu_data,
            )

        # Decode common read responses
        values: List[int] = []
        if actual_fc in (0x01, 0x02):
            # Read Coils / Discrete Inputs: byte_count + coil bytes
            if pdu_data:
                byte_count = pdu_data[0]
                coil_bytes = pdu_data[1:1 + byte_count]
                for i, b in enumerate(coil_bytes):
                    for bit in range(8):
                        values.append((b >> bit) & 1)

        elif actual_fc in (0x03, 0x04):
            # Read Holding / Input Registers: byte_count + register pairs
            if pdu_data:
                byte_count = pdu_data[0]
                for i in range(0, byte_count, 2):
                    if i + 2 <= len(pdu_data[1:]) + 1:
                        values.append(struct.unpack_from(">H", pdu_data, 1 + i)[0])

        elif actual_fc in (0x05, 0x06, 0x0F, 0x10):
            # Write responses echo start/count
            if len(pdu_data) >= 4:
                start_addr = struct.unpack_from(">H", pdu_data, 0)[0]
                qty = struct.unpack_from(">H", pdu_data, 2)[0]
                values = [start_addr, qty]

        return ModbusResponse(
            success=True,
            function_code=actual_fc,
            fc_name=FC_NAMES.get(actual_fc, f"FC{actual_fc:02X}"),
            raw_data=pdu_data,
            values=values,
        )


# ---------------------------------------------------------------------------
# TCP client
# ---------------------------------------------------------------------------

class ModbusTcpClient:
    """Modbus/TCP client with connection management and retry.

    Usage:
        client = ModbusTcpClient("192.168.0.1", unit_id=1)
        if client.connect():
            resp = client.read_holding_registers(start=0, count=10)
            print(resp.values)
            client.disconnect()
    """

    def __init__(
        self,
        host: str,
        port: int = MODBUS_TCP_PORT,
        unit_id: int = 1,
        timeout: float = 3.0,
    ) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._builder = ModbusTcpFrameBuilder(unit_id=unit_id)

    def connect(self) -> bool:
        """Establish TCP connection to Modbus slave."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            return True
        except Exception:
            self._sock = None
            return False

    def disconnect(self) -> None:
        """Close TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send_recv(self, frame: bytes) -> bytes:
        """Send frame and receive response."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        self._sock.sendall(frame)
        resp = b""
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) >= 8:
                    # Check if we have the full response
                    expected_len = struct.unpack_from(">H", resp, 4)[0] + 6
                    if len(resp) >= expected_len:
                        break
        except socket.timeout:
            pass
        return resp

    def _request(self, fc: int, **kwargs) -> ModbusResponse:
        """Send request and parse response."""
        frame = self._builder.build_request(fc, **kwargs)
        try:
            raw = self._send_recv(frame)
            return ModbusTcpParser.parse(raw, expected_fc=fc)
        except Exception as exc:
            return ModbusResponse(
                success=False,
                function_code=fc,
                fc_name=FC_NAMES.get(fc, f"FC{fc:02X}"),
                error=str(exc),
            )

    def read_coils(self, start: int = 0, count: int = 1) -> ModbusResponse:
        """FC01 - Read Coils."""
        return self._request(0x01, start=start, count=count)

    def read_discrete_inputs(self, start: int = 0, count: int = 1) -> ModbusResponse:
        """FC02 - Read Discrete Inputs."""
        return self._request(0x02, start=start, count=count)

    def read_holding_registers(self, start: int = 0, count: int = 1) -> ModbusResponse:
        """FC03 - Read Holding Registers."""
        return self._request(0x03, start=start, count=count)

    def read_input_registers(self, start: int = 0, count: int = 1) -> ModbusResponse:
        """FC04 - Read Input Registers."""
        return self._request(0x04, start=start, count=count)

    def write_single_coil(self, address: int, value: bool) -> ModbusResponse:
        """FC05 - Write Single Coil."""
        return self._request(0x05, start=address, value=1 if value else 0)

    def write_single_register(self, address: int, value: int) -> ModbusResponse:
        """FC06 - Write Single Register."""
        return self._request(0x06, start=address, value=value)

    def write_multiple_coils(self, start: int, values: List[int]) -> ModbusResponse:
        """FC15 - Write Multiple Coils."""
        return self._request(0x0F, start=start, values=values)

    def write_multiple_registers(self, start: int, values: List[int]) -> ModbusResponse:
        """FC16 - Write Multiple Registers."""
        return self._request(0x10, start=start, values=values)

    def read_device_id(self) -> ModbusResponse:
        """FC43/0x2B - Read Device Identification (MEI)."""
        return self._request(0x2B)

    def report_server_id(self) -> ModbusResponse:
        """FC17 - Report Server ID."""
        return self._request(0x11)

    def get_comm_event_counter(self) -> ModbusResponse:
        """FC11 - Get Comm Event Counter."""
        return self._request(0x0B)
