#!/usr/bin/env python3
"""
modbus_simulator_ctl.py - Python headless controller for Modbus-Process-Simulator.

Provides a Python API to control and interact with a running
Modbus-Process-Simulator (Modbus Process Simulator) instance or any Modbus/TCP slave
over standard Modbus protocol.

Features:
    - Connect to Modbus/TCP slave (Modbus Process Simulator headless or real device)
    - Read/write coils and registers programmatically
    - Run scenario scripts: ramp values, toggle coils, simulate sensor patterns
    - Compatible with Modbus Process Simulator -loadFile + -hide + -portNumber headless mode

Usage (standalone test against Modbus Process Simulator):
    # Start Modbus Process Simulator headless:
    # java -jar ModbusProcessSimulator.jar -loadFile scenario.mpsx -hide -portNumber 502
    # Then:
    python modbus_simulator_ctl.py --host localhost --port 502 --scenario ramp

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import argparse
import math
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"


class ModbusController:
    """Python Modbus/TCP client for programmatic control of Modbus slaves.

    Provides read/write operations compatible with Modbus-Process-Simulator
    (Modbus Process Simulator) and real Modbus/TCP devices.

    Args:
        host: Target Modbus/TCP host.
        port: TCP port (default 502).
        unit_id: Modbus Unit ID (default 1).
        timeout: Socket timeout in seconds.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 502,
        unit_id: int = 1,
        timeout: float = 5.0,
    ) -> None:
        if not host or len(host) > 253:
            raise ValueError("host must be a non-empty DNS name or IP address")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if not 1 <= unit_id <= 247:
            raise ValueError("unit_id must be between 1 and 247")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self._tx_id: int = 0
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establish TCP connection to Modbus slave.

        Returns:
            True if connected, False on failure.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            return True
        except Exception as exc:
            print(f"[!] Connect failed: {exc}")
            self._sock = None
            return False

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send_recv(self, pdu: bytes) -> Optional[bytes]:
        """Wrap PDU in MBAP header, send, and return raw response."""
        if self._sock is None:
            return None
        if not 1 <= len(pdu) <= 253:
            raise ValueError("PDU length must be between 1 and 253 bytes")
        self._tx_id = (self._tx_id + 1) & 0xFFFF
        frame = struct.pack(">HHHB", self._tx_id, 0, len(pdu) + 1, self.unit_id) + pdu
        try:
            self._sock.sendall(frame)
            header = self._recv_exact(7)
            tx_id, protocol_id, length, unit_id = struct.unpack(">HHHB", header)
            if tx_id != self._tx_id or protocol_id != 0 or unit_id != self.unit_id:
                raise ValueError("invalid Modbus/TCP response header")
            if not 2 <= length <= 254:
                raise ValueError(f"invalid Modbus/TCP response length: {length}")
            return header + self._recv_exact(length - 1)
        except (OSError, ValueError) as exc:
            print(f"[!] Communication error: {exc}")
            self.disconnect()
            return None

    def _recv_exact(self, size: int) -> bytes:
        """Receive exactly size bytes or fail if the connection closes."""
        if self._sock is None:
            raise OSError("socket is not connected")
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self._sock.recv(size - len(chunks))
            if not chunk:
                raise OSError(
                    f"connection closed after {len(chunks)} of {size} bytes"
                )
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _validate_range(start: int, count: int, maximum_count: int) -> None:
        if not 0 <= start <= 65535:
            raise ValueError("start address must be between 0 and 65535")
        if not 1 <= count <= maximum_count:
            raise ValueError(f"count must be between 1 and {maximum_count}")
        if start + count > 65536:
            raise ValueError("requested address range exceeds 65535")

    def read_coils(self, start: int, count: int) -> Optional[List[bool]]:
        """Read coil states (FC01).

        Args:
            start: Starting coil address.
            count: Number of coils to read.

        Returns:
            List of bool values or None on error.
        """
        self._validate_range(start, count, 2000)
        pdu = struct.pack(">BHH", 0x01, start, count)
        resp = self._send_recv(pdu)
        if resp is None or len(resp) < 10:
            return None
        if resp[7] & 0x80:
            print(f"[!] FC01 exception: 0x{resp[8]:02X}")
            return None
        byte_count = resp[8]
        if byte_count != (count + 7) // 8 or len(resp) != 9 + byte_count:
            print("[!] FC01 malformed response")
            return None
        coil_bytes = resp[9:9 + byte_count]
        coils = []
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            coils.append(bool((coil_bytes[byte_idx] >> bit_idx) & 1))
        return coils

    def read_holding_registers(self, start: int, count: int) -> Optional[List[int]]:
        """Read holding register values (FC03).

        Args:
            start: Starting register address.
            count: Number of registers to read.

        Returns:
            List of int values (0-65535) or None on error.
        """
        self._validate_range(start, count, 125)
        pdu = struct.pack(">BHH", 0x03, start, count)
        resp = self._send_recv(pdu)
        if resp is None or len(resp) < 10:
            return None
        if resp[7] & 0x80:
            print(f"[!] FC03 exception: 0x{resp[8]:02X}")
            return None
        byte_count = resp[8]
        if byte_count != count * 2 or len(resp) != 9 + byte_count:
            print("[!] FC03 malformed response")
            return None
        values = []
        for i in range(0, byte_count, 2):
            values.append(struct.unpack_from(">H", resp, 9 + i)[0])
        return values

    def write_single_coil(self, address: int, value: bool) -> bool:
        """Write a single coil (FC05).

        Args:
            address: Coil address.
            value: True=ON (0xFF00), False=OFF (0x0000).

        Returns:
            True on success.
        """
        self._validate_range(address, 1, 1)
        coil_val = 0xFF00 if value else 0x0000
        pdu = struct.pack(">BHH", 0x05, address, coil_val)
        resp = self._send_recv(pdu)
        if resp is None or len(resp) != 12:
            return False
        if resp[7] & 0x80:
            print(f"[!] FC05 exception: 0x{resp[8]:02X}")
            return False
        return resp[7:] == pdu

    def write_single_register(self, address: int, value: int) -> bool:
        """Write a single register (FC06).

        Args:
            address: Register address.
            value: Register value (0-65535).

        Returns:
            True on success.
        """
        self._validate_range(address, 1, 1)
        if not 0 <= value <= 65535:
            raise ValueError("register value must be between 0 and 65535")
        pdu = struct.pack(">BHH", 0x06, address, value)
        resp = self._send_recv(pdu)
        if resp is None or len(resp) != 12:
            return False
        if resp[7] & 0x80:
            print(f"[!] FC06 exception: 0x{resp[8]:02X}")
            return False
        return resp[7:] == pdu

    def write_multiple_registers(self, start: int, values: List[int]) -> bool:
        """Write multiple consecutive registers (FC16).

        Args:
            start: Starting register address.
            values: List of values (0-65535 each).

        Returns:
            True on success.
        """
        count = len(values)
        self._validate_range(start, count, 123)
        if any(not isinstance(value, int) or not 0 <= value <= 65535 for value in values):
            raise ValueError("all register values must be integers between 0 and 65535")
        byte_count = count * 2
        reg_bytes = b"".join(struct.pack(">H", v) for v in values)
        pdu = struct.pack(">BHHB", 0x10, start, count, byte_count) + reg_bytes
        resp = self._send_recv(pdu)
        if resp is None or len(resp) != 12:
            return False
        if resp[7] & 0x80:
            print(f"[!] FC16 exception: 0x{resp[8]:02X}")
            return False
        return resp[7:] == struct.pack(">BHH", 0x10, start, count)


# ---------------------------------------------------------------------------
# Scenario library
# ---------------------------------------------------------------------------

def scenario_ramp(ctrl: ModbusController, reg_start: int = 0, reg_count: int = 4,
                  min_val: int = 0, max_val: int = 1000, steps: int = 20,
                  delay: float = 0.5) -> None:
    """Ramp register values from min to max and back.

    Useful for simulating sensor ramps (temperature, pressure, flow).

    Args:
        ctrl: Connected ModbusController instance.
        reg_start: First register address to write.
        reg_count: Number of registers to vary.
        min_val: Minimum register value.
        max_val: Maximum register value.
        steps: Number of steps per ramp direction.
        delay: Seconds between steps.
    """
    print(f"[*] Scenario: RAMP reg {reg_start}..{reg_start+reg_count-1} "
          f"range {min_val}..{max_val}, {steps} steps")
    if reg_count < 1 or steps < 1 or min_val >= max_val:
        raise ValueError("ramp requires reg_count >= 1, steps >= 1 and min_val < max_val")
    step_size = max(1, (max_val - min_val) // steps)

    all_values = (
        list(range(min_val, max_val, step_size))
        + list(range(max_val, min_val, -step_size))
    )

    for v in all_values:
        vals = [v + i * max(1, (max_val - min_val) // (reg_count * steps))
                for i in range(reg_count)]
        ctrl.write_multiple_registers(reg_start, vals)
        current = ctrl.read_holding_registers(reg_start, reg_count)
        print(f"  Write {vals} -> Read {current}")
        time.sleep(delay)


def scenario_sine(ctrl: ModbusController, reg: int = 0, amplitude: int = 500,
                  offset: int = 500, cycles: int = 2, delay: float = 0.1) -> None:
    """Write a sine wave pattern to a single register.

    Args:
        ctrl: Connected ModbusController instance.
        reg: Register address.
        amplitude: Sine amplitude (peak value = offset + amplitude).
        offset: DC offset (centre value).
        cycles: Number of complete sine cycles.
        delay: Seconds between samples.
    """
    steps = int(cycles * 36)  # 10 degree resolution
    print(f"[*] Scenario: SINE reg {reg}, amplitude {amplitude}, offset {offset}")
    for i in range(steps):
        v = int(offset + amplitude * math.sin(2 * math.pi * i / 36))
        ctrl.write_single_register(reg, max(0, min(65535, v)))
        time.sleep(delay)
    print("[+] Sine scenario complete.")


def scenario_toggle(ctrl: ModbusController, coil: int = 0, count: int = 10,
                    delay: float = 0.5) -> None:
    """Toggle a coil on/off repeatedly.

    Args:
        ctrl: Connected ModbusController instance.
        coil: Coil address.
        count: Number of toggle cycles.
        delay: Seconds between toggles.
    """
    print(f"[*] Scenario: TOGGLE coil {coil} x{count}")
    state = False
    for i in range(count * 2):
        ctrl.write_single_coil(coil, state)
        current = ctrl.read_coils(coil, 1)
        print(f"  Coil {coil} = {state} -> Read {current}")
        state = not state
        time.sleep(delay)
    print("[+] Toggle scenario complete.")


def scenario_status(ctrl: ModbusController) -> None:
    """Print current register and coil status for quick sanity check."""
    print("[*] Scenario: STATUS")
    regs = ctrl.read_holding_registers(0, 8)
    print(f"  Holding registers [0-7]: {regs}")
    coils = ctrl.read_coils(0, 4)
    print(f"  Coils [0-3]: {coils}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

_SCENARIOS = {
    "ramp":   scenario_ramp,
    "sine":   scenario_sine,
    "toggle": scenario_toggle,
    "status": scenario_status,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Python headless controller for Modbus-Process-Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scenarios:\n"
            "  ramp   - ramp holding registers 0-3 from 0 to 1000\n"
            "  sine   - sine wave on holding register 0\n"
            "  toggle - toggle coil 0 ten times\n"
            "  status - print current register and coil values\n\n"
            "Start Modbus Process Simulator headless first:\n"
            "  java -jar ModbusProcessSimulator.jar -loadFile scenario.mpsx -hide -portNumber 502"
        ),
    )
    parser.add_argument("--host", default="localhost", help="Modbus/TCP host (default: localhost)")
    parser.add_argument("--port", type=int, default=502, help="Modbus/TCP port (default: 502)")
    parser.add_argument("--unit", type=int, default=1, help="Modbus Unit ID (default: 1)")
    parser.add_argument("--scenario", choices=list(_SCENARIOS.keys()), default="status",
                        help="Scenario to run (default: status)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between steps in seconds")
    args = parser.parse_args()

    ctrl = ModbusController(host=args.host, port=args.port, unit_id=args.unit)
    print(f"[*] Connecting to {args.host}:{args.port} (Unit ID {args.unit}) ...")
    if not ctrl.connect():
        print("[-] Connection failed. Is the Modbus slave running?")
        return

    print(f"[+] Connected. Running scenario: {args.scenario}")
    fn = _SCENARIOS[args.scenario]
    if args.scenario in ("ramp", "sine", "toggle"):
        fn(ctrl, delay=args.delay)
    else:
        fn(ctrl)

    ctrl.disconnect()
    print("[*] Done.")


if __name__ == "__main__":
    main()
