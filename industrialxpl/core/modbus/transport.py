"""Modbus/TCP transport layer — raw socket connection with retry and timing support."""

from __future__ import annotations

import socket
import struct
import time
from typing import Optional, List

from industrialxpl.core.modbus.timing import TimingProfile, DEFAULT_TIMING

_PROTOCOL_ID = 0x0000


def modbus_connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    """Open a TCP connection to a Modbus device.

    Returns a connected socket or None on failure.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


class ModbusTCPSocket:
    """Managed Modbus/TCP socket with automatic MBAP framing, retry and timing."""

    def __init__(
        self,
        host: str,
        port: int,
        unit_id: int = 1,
        timing: TimingProfile = DEFAULT_TIMING,
    ) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timing = timing
        self._sock: Optional[socket.socket] = None
        self._tx_id = 0

    def _next_tx(self) -> int:
        self._tx_id = (self._tx_id + 1) & 0xFFFF
        return self._tx_id

    def connect(self) -> bool:
        self._sock = modbus_connect(self.host, self.port, self.timing.socket_timeout)
        return self._sock is not None

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> "ModbusTCPSocket":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _build_adu(self, pdu: bytes) -> bytes:
        """Wrap PDU in Modbus/TCP MBAP header."""
        tx = self._next_tx()
        return struct.pack(">HHHB", tx, _PROTOCOL_ID, len(pdu) + 1, self.unit_id) + pdu

    def send_pdu(self, pdu: bytes, recv_size: int = 256) -> Optional[bytes]:
        """Send PDU with retry logic; returns raw response bytes or None."""
        adu = self._build_adu(pdu)
        for attempt in range(self.timing.retries):
            try:
                if self._sock is None:
                    if not self.connect():
                        return None
                self._sock.sendall(adu)
                data = b""
                deadline = time.monotonic() + self.timing.max_rtt_timeout
                while len(data) < 6 and time.monotonic() < deadline:
                    chunk = self._sock.recv(recv_size)
                    if not chunk:
                        break
                    data += chunk
                if data:
                    self.timing.sleep()
                    return data
            except (socket.timeout, OSError):
                self.close()
                if attempt < self.timing.retries - 1:
                    time.sleep(min(0.5 * (attempt + 1), 2.0))
        return None

    # ── Convenience FC builders ───────────────────────────────────────────────

    def read_coils(self, address: int, quantity: int) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x01, address, quantity)
        return self.send_pdu(pdu)

    def read_discrete_inputs(self, address: int, quantity: int) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x02, address, quantity)
        return self.send_pdu(pdu)

    def read_holding_registers(self, address: int, quantity: int) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x03, address, quantity)
        return self.send_pdu(pdu)

    def read_input_registers(self, address: int, quantity: int) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x04, address, quantity)
        return self.send_pdu(pdu)

    def write_single_coil(self, address: int, value: bool) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x05, address, 0xFF00 if value else 0x0000)
        return self.send_pdu(pdu)

    def write_single_register(self, address: int, value: int) -> Optional[bytes]:
        pdu = struct.pack(">BHH", 0x06, address, value & 0xFFFF)
        return self.send_pdu(pdu)

    def report_server_id(self) -> Optional[bytes]:
        pdu = struct.pack(">B", 0x11)
        return self.send_pdu(pdu)

    def read_device_identification(self, object_id: int = 0x00) -> Optional[bytes]:
        pdu = struct.pack(">BBBBB", 0x2B, 0x0E, 0x01, object_id, 0x00)
        return self.send_pdu(pdu)

    def send_fc(self, fc: int, address: int, quantity: int) -> Optional[bytes]:
        """Generic read FC dispatcher for FC 1-4."""
        _dispatch = {
            1: self.read_coils,
            2: self.read_discrete_inputs,
            3: self.read_holding_registers,
            4: self.read_input_registers,
        }
        fn = _dispatch.get(fc)
        if fn is None:
            raise ValueError("FC{} not supported by send_fc (use send_pdu for custom)".format(fc))
        return fn(address, quantity)


def scan_ports(host: str, ports: List[int], timeout: float) -> List[int]:
    """Return list of open ports from the given list."""
    open_ports = []
    for port in ports:
        sock = modbus_connect(host, port, timeout)
        if sock:
            sock.close()
            open_ports.append(port)
    return open_ports


def parse_port_expression(expr: str) -> List[int]:
    """Parse a port expression like '502', '502,510', '500-510'.

    Returns sorted list of unique port numbers (1-65535).
    """
    ports = set()
    for token in expr.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError("Invalid port range: '{}'".format(token))
            if not (1 <= start <= end <= 65535):
                raise ValueError("Port range {}-{} out of bounds (1-65535)".format(start, end))
            if end - start > 1000:
                raise ValueError(
                    "Port range {}-{} too wide (max 1000 per range for safety)".format(start, end)
                )
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(token)
            except ValueError:
                raise ValueError("Invalid port: '{}'".format(token))
            if not 1 <= p <= 65535:
                raise ValueError("Port {} out of bounds (1-65535)".format(p))
            ports.add(p)
    if not ports:
        raise ValueError("No ports resolved from '{}'".format(expr))
    return sorted(ports)
