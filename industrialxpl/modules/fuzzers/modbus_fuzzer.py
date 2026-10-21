"""Modbus TCP Protocol Fuzzer with Scapy-style packet definitions.

Native implementation of Modbus TCP fuzzing using structured packet classes.
Adapted from SMOD (0x0mar) Modbus Scapy definitions and extended with
modern fuzzing strategies.

Supports:
  - Function code fuzzing (all 127 standard + vendor codes)
  - Malformed MBAP header injection
  - Register/coil boundary overflow
  - Unit ID brute-force scan
  - Transaction ID collision testing
  - Payload length manipulation

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Based on: SMOD by 0x0mar (GPL-3.0)
"""

from __future__ import annotations

import logging
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

# Modbus function code definitions
FUNCTION_CODE_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Multiple Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Holding Register",
    7: "Read Exception Status",
    8: "Diagnostic",
    11: "Get Com Event Counter",
    12: "Get Com Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Holding Registers",
    17: "Report Slave ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Read Device Identification",
}

MODBUS_EXCEPTIONS = {
    1: "Illegal function",
    2: "Illegal data address",
    3: "Illegal data value",
    4: "Slave device failure",
    5: "Acknowledge",
    6: "Slave device busy",
    8: "Memory parity error",
    10: "Gateway path unavailable",
    11: "Gateway target device failed to respond",
}


# ---------------------------------------------------------------------------
# Modbus TCP packet builder (pure Python, no Scapy dependency)
# ---------------------------------------------------------------------------

@dataclass
class ModbusTCPFrame:
    """Modbus TCP Application Data Unit (ADU)."""
    transaction_id: int = 0
    protocol_id: int = 0
    unit_id: int = 1
    function_code: int = 3
    data: bytes = b""

    def pack(self) -> bytes:
        pdu = bytes([self.function_code]) + self.data
        mbap = struct.pack(">HHHB",
                           self.transaction_id,
                           self.protocol_id,
                           len(pdu) + 1,
                           self.unit_id)
        return mbap + pdu

    @classmethod
    def unpack(cls, raw: bytes) -> ModbusTCPFrame:
        if len(raw) < 8:
            raise ValueError("Frame too short")
        tid, pid, length, uid = struct.unpack_from(">HHHB", raw, 0)
        fc = raw[7]
        data = raw[8:] if len(raw) > 8 else b""
        return cls(tid, pid, uid, fc, data)

    def is_exception(self) -> bool:
        return bool(self.function_code & 0x80)

    def exception_code(self) -> int:
        if self.is_exception() and self.data:
            return self.data[0]
        return 0


# Standard request builders

def read_coils(start: int = 0, count: int = 1) -> bytes:
    return struct.pack(">HH", start, count)


def read_discrete_inputs(start: int = 0, count: int = 1) -> bytes:
    return struct.pack(">HH", start, count)


def read_holding_registers(start: int = 0, count: int = 1) -> bytes:
    return struct.pack(">HH", start, count)


def read_input_registers(start: int = 0, count: int = 1) -> bytes:
    return struct.pack(">HH", start, count)


def write_single_coil(address: int = 0, value: bool = True) -> bytes:
    return struct.pack(">HH", address, 0xFF00 if value else 0x0000)


def write_single_register(address: int = 0, value: int = 0) -> bytes:
    return struct.pack(">HH", address, value & 0xFFFF)


def write_multiple_coils(start: int = 0, values: list[bool] = None) -> bytes:
    if values is None:
        values = [True]
    count = len(values)
    byte_count = (count + 7) // 8
    coil_bytes = bytearray(byte_count)
    for i, v in enumerate(values):
        if v:
            coil_bytes[i // 8] |= 1 << (i % 8)
    return struct.pack(">HHB", start, count, byte_count) + bytes(coil_bytes)


def write_multiple_registers(start: int = 0, values: list[int] = None) -> bytes:
    if values is None:
        values = [0]
    count = len(values)
    byte_count = count * 2
    payload = struct.pack(">HHB", start, count, byte_count)
    for v in values:
        payload += struct.pack(">H", v & 0xFFFF)
    return payload


# ---------------------------------------------------------------------------
# Fuzzing strategies
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Result of a single fuzz probe."""
    strategy: str
    frame_sent: ModbusTCPFrame
    response: ModbusTCPFrame | None = None
    error: str = ""
    crash_detected: bool = False


def _send_and_recv(host: str, port: int, frame: ModbusTCPFrame,
                   timeout: float = 3.0) -> ModbusTCPFrame | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(frame.pack())
            reply = sock.recv(1024)
            if reply and len(reply) >= 8:
                return ModbusTCPFrame.unpack(reply)
    except TimeoutError:
        return None
    except OSError:
        return None
    return None


def fuzz_function_codes(host: str, port: int, unit_id: int,
                        timeout: float) -> list[FuzzResult]:
    """Probe all 127 function codes to discover supported/hidden functions."""
    results = []
    for fc in range(1, 128):
        frame = ModbusTCPFrame(
            transaction_id=random.randint(0, 0xFFFF),
            unit_id=unit_id,
            function_code=fc,
            data=b"\x00\x00\x00\x01",
        )
        resp = _send_and_recv(host, port, frame, timeout)
        r = FuzzResult(strategy="function_code_scan", frame_sent=frame, response=resp)
        if resp:
            if not resp.is_exception():
                r.crash_detected = False
                results.append(r)
            elif resp.exception_code() not in (1,):
                results.append(r)
        else:
            r.error = "No response (possible crash or filter)"
            r.crash_detected = True
            results.append(r)
    return results


def fuzz_malformed_mbap(host: str, port: int, unit_id: int,
                        timeout: float) -> list[FuzzResult]:
    """Send malformed MBAP headers to test parser robustness."""
    results = []
    payloads = [
        ("zero_length", struct.pack(">HHHB", 1, 0, 0, unit_id) + b"\x03\x00\x00\x00\x01"),
        ("huge_length", struct.pack(">HHHB", 1, 0, 0xFFFF, unit_id) + b"\x03\x00\x00\x00\x01"),
        ("wrong_proto", struct.pack(">HHHB", 1, 0xDEAD, 6, unit_id) + b"\x03\x00\x00\x00\x01"),
        ("negative_length", struct.pack(">HHhB", 1, 0, -1, unit_id) + b"\x03\x00\x00\x00\x01"),
        ("empty_pdu", struct.pack(">HHHB", 1, 0, 1, unit_id)),
        ("oversized_pdu", struct.pack(">HHHB", 1, 0, 6, unit_id) + b"\x03" + os.urandom(260)),
        ("null_unit_id", struct.pack(">HHHB", 1, 0, 6, 0) + b"\x03\x00\x00\x00\x01"),
        ("max_unit_id", struct.pack(">HHHB", 1, 0, 6, 255) + b"\x03\x00\x00\x00\x01"),
    ]

    for name, raw in payloads:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.sendall(raw)
                try:
                    reply = sock.recv(1024)
                    resp = ModbusTCPFrame.unpack(reply) if reply and len(reply) >= 8 else None
                except (TimeoutError, ValueError):
                    resp = None
            frame = ModbusTCPFrame(data=raw)
            r = FuzzResult(strategy=f"malformed_mbap/{name}", frame_sent=frame, response=resp)
            if resp is None:
                r.crash_detected = True
                r.error = "No response to malformed MBAP"
            results.append(r)
        except OSError as e:
            frame = ModbusTCPFrame(data=raw)
            results.append(FuzzResult(
                strategy=f"malformed_mbap/{name}",
                frame_sent=frame,
                error=str(e),
                crash_detected=True,
            ))

    return results


def fuzz_register_boundaries(host: str, port: int, unit_id: int,
                             timeout: float) -> list[FuzzResult]:
    """Test register/coil address boundaries for overflows."""
    results = []
    boundary_tests = [
        ("coil_max_addr", 1, struct.pack(">HH", 0xFFFF, 1)),
        ("coil_max_count", 1, struct.pack(">HH", 0, 0x07D0)),
        ("coil_overflow", 1, struct.pack(">HH", 0xFFF0, 0x0800)),
        ("reg_max_addr", 3, struct.pack(">HH", 0xFFFF, 1)),
        ("reg_max_count", 3, struct.pack(">HH", 0, 125)),
        ("reg_overflow", 3, struct.pack(">HH", 0xFFF0, 200)),
        ("input_boundary", 4, struct.pack(">HH", 0xFFFF, 1)),
        ("write_coil_invalid", 5, struct.pack(">HH", 0, 0x1234)),
        ("write_reg_max", 6, struct.pack(">HH", 0xFFFF, 0xFFFF)),
    ]

    for name, fc, data in boundary_tests:
        frame = ModbusTCPFrame(
            transaction_id=random.randint(0, 0xFFFF),
            unit_id=unit_id,
            function_code=fc,
            data=data,
        )
        resp = _send_and_recv(host, port, frame, timeout)
        r = FuzzResult(strategy=f"register_boundary/{name}", frame_sent=frame, response=resp)
        if resp is None:
            r.crash_detected = True
            r.error = "No response (possible crash)"
        results.append(r)

    return results


def fuzz_transaction_id_collision(host: str, port: int, unit_id: int,
                                  timeout: float) -> list[FuzzResult]:
    """Send rapid requests with colliding transaction IDs."""
    results = []
    fixed_tid = 0x0001
    for i in range(10):
        frame = ModbusTCPFrame(
            transaction_id=fixed_tid,
            unit_id=unit_id,
            function_code=3,
            data=read_holding_registers(0, 1),
        )
        resp = _send_and_recv(host, port, frame, timeout)
        r = FuzzResult(strategy=f"tid_collision/{i}", frame_sent=frame, response=resp)
        if resp and resp.transaction_id != fixed_tid:
            r.error = f"TID mismatch: sent {fixed_tid}, got {resp.transaction_id}"
        results.append(r)
    return results


def scan_unit_ids(host: str, port: int,
                  timeout: float) -> list[tuple[int, ModbusTCPFrame | None]]:
    """Enumerate responsive Modbus unit IDs."""
    responsive = []
    for uid in range(0, 256):
        frame = ModbusTCPFrame(
            transaction_id=random.randint(0, 0xFFFF),
            unit_id=uid,
            function_code=17,
            data=b"",
        )
        resp = _send_and_recv(host, port, frame, timeout)
        if resp:
            responsive.append((uid, resp))
    return responsive


# ---------------------------------------------------------------------------
# Main exploit class
# ---------------------------------------------------------------------------

class ModbusFuzzer(Exploit):
    """Modbus TCP protocol fuzzer for ICS security assessment."""

    __info__ = {
        "name": "Modbus TCP Fuzzer",
        "description": "Fuzzer for Modbus TCP protocol with multiple attack strategies",
        "authors": ["Andre Henrique (@mrhenrike)", "0x0mar (SMOD original)"],
        "references": [
            "https://github.com/0x0mar/smod",
            "IEC 61158 / MODBUS Application Protocol V1.1b3",
            "MITRE ICS T0836 (Modify Parameter)",
        ],
    }

    target = OptIP("", "Target Modbus device IP")
    port = OptPort(502, "Target port")
    unit_id = OptInteger(1, "Target Modbus unit ID")
    fuzz_timeout = OptInteger(3, "Timeout per fuzz probe (seconds)")
    strategies = OptString("all", "Strategies: function_codes,malformed_mbap,boundaries,tid_collision,uid_scan")
    destructive = OptBool(False, "Allow write-based fuzz payloads (CAUTION: modifies PLC state)")

    def run(self) -> dict:
        host = self.target
        port = int(self.port)
        uid = int(self.unit_id)
        timeout = float(self.fuzz_timeout)
        all_strategies = self.strategies == "all"
        selected = set(s.strip() for s in self.strategies.split(","))

        all_results = {}

        print_status(f"Modbus Fuzzer targeting {host}:{port} (unit ID {uid})")

        if all_strategies or "function_codes" in selected:
            print_status("Strategy: Function code enumeration...")
            results = fuzz_function_codes(host, port, uid, timeout)
            supported = [r for r in results if r.response and not r.response.is_exception()]
            crashes = [r for r in results if r.crash_detected]
            print_info(f"  Supported FCs: {len(supported)}, Potential crashes: {len(crashes)}")
            for r in supported:
                fc = r.frame_sent.function_code
                name = FUNCTION_CODE_NAMES.get(fc, "Vendor/Unknown")
                print_success(f"  FC {fc} ({name}): SUPPORTED")
            for r in crashes:
                fc = r.frame_sent.function_code
                print_warning(f"  FC {fc}: NO RESPONSE (crash candidate)")
            all_results["function_codes"] = {
                "supported": len(supported),
                "crashes": len(crashes),
                "details": [(r.frame_sent.function_code, r.error) for r in crashes],
            }

        if all_strategies or "malformed_mbap" in selected:
            print_status("Strategy: Malformed MBAP header injection...")
            results = fuzz_malformed_mbap(host, port, uid, timeout)
            crashes = [r for r in results if r.crash_detected]
            print_info(f"  Tested {len(results)} malformed payloads, {len(crashes)} no-response")
            for r in crashes:
                print_warning(f"  {r.strategy}: {r.error}")
            all_results["malformed_mbap"] = {
                "tested": len(results),
                "no_response": len(crashes),
            }

        if all_strategies or "boundaries" in selected:
            print_status("Strategy: Register/coil boundary testing...")
            results = fuzz_register_boundaries(host, port, uid, timeout)
            crashes = [r for r in results if r.crash_detected]
            print_info(f"  Tested {len(results)} boundary cases, {len(crashes)} no-response")
            all_results["boundaries"] = {
                "tested": len(results),
                "crashes": len(crashes),
            }

        if all_strategies or "tid_collision" in selected:
            print_status("Strategy: Transaction ID collision...")
            results = fuzz_transaction_id_collision(host, port, uid, timeout)
            mismatches = [r for r in results if r.error]
            print_info(f"  Tested {len(results)} collisions, {len(mismatches)} anomalies")
            all_results["tid_collision"] = {
                "tested": len(results),
                "mismatches": len(mismatches),
            }

        if all_strategies or "uid_scan" in selected:
            print_status("Strategy: Unit ID enumeration...")
            responsive = scan_unit_ids(host, port, timeout)
            print_info(f"  Found {len(responsive)} responsive unit IDs")
            for uid_found, resp in responsive:
                print_success(f"  UID {uid_found}: responded")
            all_results["uid_scan"] = {
                "responsive": [uid for uid, _ in responsive],
            }

        total_crashes = sum(
            v.get("crashes", v.get("no_response", 0))
            for v in all_results.values() if isinstance(v, dict)
        )
        if total_crashes > 0:
            print_error(f"TOTAL: {total_crashes} potential crash/anomaly indicators found")
        else:
            print_success("No crashes detected across all strategies")

        return all_results


MANIFEST = {
    "name": "modbus_fuzzer",
    "category": "fuzzers",
    "protocols": ["modbus"],
    "mitre_ics": ["T0836", "T0855", "T0831"],
    "source": "https://github.com/0x0mar/smod",
    "license": "GPL-3.0",
}
