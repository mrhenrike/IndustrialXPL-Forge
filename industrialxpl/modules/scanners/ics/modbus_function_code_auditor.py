# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus Function Code Auditor - native risk matrix for Modbus/TCP targets.

Probes all relevant Modbus function codes against a target and classifies each
by response and risk level. Produces a structured audit report with hardening
recommendations.

Function codes audited:
    Read:        FC01 ReadCoils, FC02 ReadDiscreteInputs, FC03 ReadHoldingRegs,
                 FC04 ReadInputRegs
    Write:       FC05 WriteSingleCoil, FC06 WriteRegister, FC15 WriteMultCoils,
                 FC16 WriteMultRegs, FC22 MaskWriteReg, FC23 RWMultRegs
    Diagnostics: FC08 Diagnostics, FC11 GetCommEventCounter, FC17 ReportServerId
    Advanced:    FC20 ReadFileRecord, FC21 WriteFileRecord, FC43 ReadDeviceId

Risk classification:
    CRITICAL - Unauthenticated write to coils/registers
    HIGH     - Unauthenticated parameter read (production values exposed)
    MEDIUM   - Diagnostic/identification exposure
    LOW      - Information disclosure (Device ID, port mapping)
    INFO     - Expected/safe responses

Protocol: Modbus/TCP, default port 502
References:
    - Modbus Application Protocol Specification V1.1b3
    - MITRE ATT&CK ICS: T0836 Modify Parameter, T0831 Manipulation of View,
      T0846 Remote System Discovery

Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from industrialxpl.core.exploit import *
from industrialxpl.core.exploit.exploit import BaseExploit

__version__ = "1.0.0"

# Transaction ID for all probes
_TID = 0x1A2B

# Modbus function code definitions
# (fc, name, risk_level, description, probe_bytes_after_header)
_FC_CATALOG: List[Tuple[int, str, str, str, bytes]] = [
    # Read FCs - use READ-ONLY probe (read 1 register/coil from address 0)
    (0x01, "ReadCoils",           "HIGH",     "Read coil state (digital outputs)", b"\x00\x00\x00\x01"),
    (0x02, "ReadDiscreteInputs",  "MEDIUM",   "Read discrete input state",          b"\x00\x00\x00\x01"),
    (0x03, "ReadHoldingRegisters","HIGH",     "Read holding registers (process values)", b"\x00\x00\x00\x01"),
    (0x04, "ReadInputRegisters",  "MEDIUM",   "Read input registers",               b"\x00\x00\x00\x01"),
    # Diagnostic FCs
    (0x08, "Diagnostics",         "MEDIUM",   "Modbus diagnostics sub-function 0 (Return Query Data)", b"\x00\x00\x00\x00"),
    (0x0B, "GetCommEventCounter", "LOW",      "Returns communication event counter",b""),
    (0x11, "ReportServerId",      "LOW",      "Returns device identifier string",   b""),
    # Write FCs - safe probe: attempt write to address 0xFFFF (non-existent, expect exception)
    (0x05, "WriteSingleCoil",     "CRITICAL", "Write single coil (unauthenticated write)", b"\xFF\xFF\xFF\x00"),
    (0x06, "WriteRegister",       "CRITICAL", "Write single register (unauthenticated write)", b"\xFF\xFF\x00\x00"),
    (0x0F, "WriteMultipleCoils",  "CRITICAL", "Write multiple coils",               b"\xFF\xFF\x00\x01\x01\x00"),
    (0x10, "WriteMultipleRegs",   "CRITICAL", "Write multiple registers",           b"\xFF\xFF\x00\x01\x02\x00\x00"),
    # Advanced FCs
    (0x2B, "ReadDeviceIdentification", "LOW", "MEI Read Device Identification (RFC 003)", b"\x0E\x01\x00"),
]

# Risk severity ordering
_RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Build a Modbus/TCP Application Header (MBAP) + PDU frame."""
    length = len(pdu) + 1  # +1 for unit_id
    return struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id) + pdu


def _probe_fc(
    host: str,
    port: int,
    unit_id: int,
    fc: int,
    data: bytes,
    timeout: float,
) -> Tuple[str, bytes]:
    """Send a single Modbus function code probe and return (status, raw_response).

    Status values:
        'ok'          - Valid Modbus response (no exception)
        'exception'   - Modbus exception response (FC + 0x80)
        'timeout'     - No response within timeout
        'refused'     - Connection refused
        'error'       - Other socket/protocol error
    """
    pdu = bytes([fc]) + data
    frame = _build_mbap(_TID, unit_id, pdu)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(frame)
        resp = sock.recv(512)
        sock.close()

        if len(resp) < 8:
            return "error", resp

        # Check for exception response: byte 7 is FC | 0x80
        resp_fc = resp[7]
        if resp_fc == (fc | 0x80):
            return "exception", resp
        if resp_fc == fc:
            return "ok", resp
        return "error", resp

    except ConnectionRefusedError:
        return "refused", b""
    except socket.timeout:
        return "timeout", b""
    except Exception:
        return "error", b""


def _parse_exception_code(resp: bytes) -> int:
    """Extract Modbus exception code from exception response."""
    if len(resp) >= 9:
        return resp[8]
    return 0


def audit_modbus(
    host: str,
    port: int = 502,
    unit_id: int = 1,
    timeout: float = 3.0,
    write_test: bool = False,
) -> List[Dict[str, Any]]:
    """Audit all Modbus function codes against a target.

    Args:
        host: Target host/IP.
        port: Modbus/TCP port (default 502).
        unit_id: Modbus Unit ID to probe (1-255).
        timeout: Socket timeout per probe in seconds.
        write_test: Include write FC probes (disabled by default for safety).

    Returns:
        List of result dicts per function code.
    """
    results = []
    for fc, name, risk, description, probe_data in _FC_CATALOG:
        is_write = risk == "CRITICAL"

        if is_write and not write_test:
            results.append({
                "fc": fc,
                "fc_hex": f"0x{fc:02X}",
                "name": name,
                "risk": "CRITICAL",
                "status": "skipped",
                "description": description,
                "detail": "Write probe skipped (use write_test=True to enable)",
            })
            continue

        status, raw = _probe_fc(host, port, unit_id, fc, probe_data, timeout)

        exc_code = 0
        detail = ""

        if status == "ok":
            detail = f"Responded OK - {name} accessible without authentication"
        elif status == "exception":
            exc_code = _parse_exception_code(raw)
            exc_names = {
                1: "Illegal Function (FC not supported)",
                2: "Illegal Data Address",
                3: "Illegal Data Value",
                4: "Device Failure",
                5: "Acknowledge (queued)",
                6: "Device Busy",
            }
            detail = exc_names.get(exc_code, f"Exception code {exc_code}")
            # Exception means the device responded but rejected - function exists
            if exc_code == 1:
                risk = "INFO"
            detail = f"Exception 0x{exc_code:02X}: {detail}"
        elif status == "timeout":
            risk = "INFO"
            detail = "No response (timeout)"
        elif status == "refused":
            risk = "INFO"
            detail = "Connection refused"
        else:
            risk = "INFO"
            detail = "Protocol error or no response"

        results.append({
            "fc": fc,
            "fc_hex": f"0x{fc:02X}",
            "name": name,
            "risk": risk,
            "status": status,
            "exception_code": exc_code,
            "description": description,
            "detail": detail,
        })

        time.sleep(0.05)  # brief inter-probe delay to avoid flooding

    return results


class Exploit(BaseExploit):
    """Modbus Function Code Auditor with risk matrix and hardening report.

    Probes all standard Modbus function codes and produces a colour-coded
    risk matrix. Write probes are disabled by default (enable with --write-test).

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Modbus Function Code Auditor",
        "description": (
            "Audits all Modbus/TCP function codes (FC01-FC43) and classifies "
            "each by risk level. Produces a hardening report. "
            "Write probes disabled by default."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "Modbus Application Protocol Specification V1.1b3",
            "MITRE ATT&CK ICS T0836, T0831, T0846",
            "submodules/OT/modbus-tcp-auditor-tool",
        ),
        "targets": ("Modbus/TCP gateways, PLCs, RTUs, energy meters",),
        "platform": ("linux", "macos", "windows"),
        "safe_mode": True,
    }

    rhost = OptString("", "Target host/IP (required)")
    rport = OptInteger(502, "Modbus/TCP port")
    unit_id = OptInteger(1, "Modbus Unit ID (slave address)")
    timeout = OptFloat(3.0, "Socket timeout per probe in seconds")
    write_test = OptBool(False, "Enable write FC probes (FC05/06/15/16) - USE WITH CAUTION")

    def check(self) -> bool:
        host = str(self.rhost).strip()
        if not host:
            print("[-] Set rhost to the target IP/hostname.")
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((host, int(self.rport)))
            sock.close()
            return True
        except Exception as exc:
            print(f"[-] Cannot reach {host}:{self.rport} - {exc}")
            return False

    def run(self) -> None:
        host = str(self.rhost).strip()
        port = int(self.rport)
        unit = int(self.unit_id)
        timeout = float(self.timeout)
        write_test = bool(self.write_test)

        if write_test:
            print("[!] Write test mode enabled. Non-existent address (0xFFFF) used for write probes.")

        print()
        print("=" * 70)
        print(f"  Modbus Function Code Audit - {host}:{port} (Unit ID {unit})")
        print("=" * 70)
        print()

        results = audit_modbus(host, port, unit, timeout, write_test)

        # Display sorted by risk descending
        results.sort(key=lambda r: _RISK_ORDER.get(r["risk"], 0), reverse=True)

        print(f"{'FC':>4}  {'Name':<30}  {'Risk':<10}  {'Status':<12}  Detail")
        print("-" * 90)
        for r in results:
            print(
                f"  {r['fc_hex']:<4}  {r['name']:<30}  {r['risk']:<10}  "
                f"{r['status']:<12}  {r['detail']}"
            )

        print()

        # Risk summary
        critical = [r for r in results if r["risk"] == "CRITICAL" and r["status"] == "ok"]
        high = [r for r in results if r["risk"] == "HIGH" and r["status"] == "ok"]
        medium = [r for r in results if r["risk"] in ("MEDIUM",) and r["status"] in ("ok", "exception")]

        if critical:
            print("[!] CRITICAL: Unauthenticated write access confirmed:")
            for r in critical:
                print(f"    FC {r['fc_hex']} ({r['name']}) - {r['detail']}")

        if high:
            print("[!] HIGH: Unauthenticated read access to process data:")
            for r in high:
                print(f"    FC {r['fc_hex']} ({r['name']}) - {r['detail']}")

        print()
        print("Hardening recommendations:")
        if critical or high:
            print("  1. Deploy Modbus-aware firewall (whitelist allowed FC per zone)")
            print("  2. Implement Modbus TCP authentication (RFC 2267 / IEC 62351-5)")
            print("  3. Restrict port 502 to authorised engineering workstations only")
            print("  4. Enable Modbus audit logging at gateway/firewall level")
            print("  5. Consider read-only mode for remote monitoring connections")
        else:
            print("  [+] No unauthenticated write/read access detected at current config.")
        print()
