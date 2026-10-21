"""PLC Scanner: Modbus TCP + S7comm device discovery and identification.

Modernized from plcscan by Dmitry Efanov / Positive Research (2012).
Ported from Python 2 to Python 3 with native socket-level protocol stacks.
No external dependencies required.

Supports:
  - Modbus TCP: unit ID enumeration, device identification (FC 0x2B/0x0E)
  - S7comm: TSAP brute-force, SZL read (module + component identification)
  - CIDR range scanning with configurable timeout

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Original: Dmitry Efanov (Positive Research), BSD License
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Modbus TCP protocol stack (pure Python 3)
# ---------------------------------------------------------------------------

class ModbusProtocolError(Exception):
    pass


class ModbusError(Exception):
    _errors = {
        0: "No reply",
        1: "ILLEGAL FUNCTION",
        2: "ILLEGAL DATA ADDRESS",
        3: "ILLEGAL DATA VALUE",
        4: "SLAVE DEVICE FAILURE",
        5: "ACKNOWLEDGE",
        6: "SLAVE DEVICE BUSY",
        8: "MEMORY PARITY ERROR",
        0x0A: "GATEWAY PATH UNAVAILABLE",
        0x0B: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
    }

    def __init__(self, code: int):
        self.code = code
        self.message = self._errors.get(code, "Unknown Error")
        super().__init__(f"[Modbus][0x{code:02x}] {self.message}")


@dataclass
class ModbusPacket:
    transaction_id: int = 0
    unit_id: int = 0
    function_id: int = 0
    data: bytes = b""

    def pack(self) -> bytes:
        return (struct.pack(">HHHBB",
                            self.transaction_id, 0,
                            len(self.data) + 2,
                            self.unit_id, self.function_id)
                + self.data)

    @classmethod
    def unpack(cls, raw: bytes) -> "ModbusPacket":
        if len(raw) < 8:
            raise ModbusProtocolError("Response too short")
        tid, _proto, length, uid, fc = struct.unpack(">HHHBB", raw[:8])
        data = raw[8:]
        pkt = cls(transaction_id=tid, unit_id=uid, function_id=fc, data=data)
        return pkt


class ModbusClient:
    """Minimal Modbus TCP client for scanning."""

    def __init__(self, ip: str, port: int = 502, uid: int = 0,
                 timeout: float = 8.0):
        self.ip = ip
        self.port = port
        self.uid = uid
        self.timeout = timeout

    def request(self, function_id: int, data: bytes = b"") -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((self.ip, self.port))
            pkt = ModbusPacket(0, self.uid, function_id, data)
            sock.sendall(pkt.pack())
            reply = sock.recv(1024)
            if not reply:
                raise ModbusError(0)
            resp = ModbusPacket.unpack(reply)
            if resp.unit_id != self.uid:
                raise ModbusProtocolError("Unexpected unit ID")
            if resp.function_id & 0x80:
                raise ModbusError(resp.data[0] if resp.data else 0)
            return resp.data

    def device_info(self) -> str:
        res = self.request(0x2B, b"\x0e\x01\x00")
        if res and len(res) > 5:
            obj_count = res[5]
            data = res[6:]
            parts = []
            for _ in range(obj_count):
                if len(data) < 2:
                    break
                obj_len = data[1]
                parts.append(data[2:2 + obj_len].decode("ascii", errors="replace"))
                data = data[2 + obj_len:]
            return " ".join(parts)
        raise ModbusProtocolError("Invalid device info response")


def scan_modbus_unit(ip: str, port: int, uid: int, timeout: float,
                     function: Optional[int] = None,
                     data: bytes = b"") -> list[str]:
    """Scan a single Modbus unit ID and return info lines."""
    client = ModbusClient(ip, port, uid, timeout)
    info = []

    if function is not None:
        try:
            resp = client.request(function, data)
            info.append(f"Response: {resp.hex()}")
        except ModbusError as e:
            if e.code:
                info.append(f"Response error: {e.message}")
            else:
                return info

    try:
        dev = client.device_info()
        info.append(f"Device: {dev}")
    except ModbusError as e:
        if e.code:
            info.append(f"Device info error: {e.message}")
        else:
            return info
    except ModbusProtocolError:
        pass

    return info


# ---------------------------------------------------------------------------
# S7comm protocol stack (pure Python 3)
# ---------------------------------------------------------------------------

class S7ProtocolError(Exception):
    pass


class S7Error(Exception):
    _errors = {
        0x05: "Address Error",
        0x0A: "Item not available",
        0x8104: "Context not supported",
        0x8500: "Wrong PDU size",
    }

    def __init__(self, code: int):
        self.code = code
        self.message = self._errors.get(code, "Unknown error")
        super().__init__(f"[S7][0x{code:x}] {self.message}")


class S7Client:
    """Minimal S7comm client for PLC scanning."""

    def __init__(self, ip: str, port: int = 102,
                 src_tsap: int = 0x0200, dst_tsap: int = 0x0201,
                 timeout: float = 8.0):
        self.ip = ip
        self.port = port
        self.src_tsap = src_tsap
        self.dst_tsap = dst_tsap
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._req_id = 0

    def connect(self) -> None:
        import random
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.ip, self.port))

        # COTP Connection Request
        cotp_cr = struct.pack(">BBHHBBBHBBHBBB",
                              17, 0xE0, 0, random.randint(1, 20), 0,
                              0xC1, 2, self.src_tsap,
                              0xC2, 2, self.dst_tsap,
                              0xC0, 1, 0x0A)
        tpkt = struct.pack(">BBH", 3, 0, len(cotp_cr) + 4) + cotp_cr
        self._sock.sendall(tpkt)
        reply = self._sock.recv(1024)
        if len(reply) < 7:
            raise S7ProtocolError("COTP CC too short")
        # Verify CC
        cotp_data = reply[4:]
        if len(cotp_data) < 2 or cotp_data[1] != 0xD0:
            raise S7ProtocolError("Not a COTP CC packet")

        # Negotiate PDU
        self._negotiate_pdu()

    def _negotiate_pdu(self, pdu_size: int = 480) -> int:
        params = struct.pack(">BBHHH", 0xF0, 0x00, 0x01, 0x01, pdu_size)
        resp = self._s7_request(0x01, params)
        _, _, pj1, pj2, neg_pdu = struct.unpack(">BBHHH", resp[:6])
        return neg_pdu

    def _s7_request(self, pdu_type: int, parameters: bytes,
                    data: bytes = b"") -> bytes:
        s7_pkt = struct.pack(">BBHHHH",
                             0x32, pdu_type, 0, self._req_id,
                             len(parameters), len(data)) + parameters + data
        cotp_dt = struct.pack(">BBB", 2, 0xF0, 0x80) + s7_pkt
        tpkt = struct.pack(">BBH", 3, 0, len(cotp_dt) + 4) + cotp_dt
        self._sock.sendall(tpkt)
        reply = self._sock.recv(4096)
        if not reply or len(reply) < 12:
            raise S7ProtocolError("S7 reply too short")
        # Parse: skip TPKT (4 bytes) + COTP DT header
        cotp_start = 4
        cotp_hdr_len = reply[cotp_start]
        s7_raw = reply[cotp_start + cotp_hdr_len + 1:]
        if len(s7_raw) < 10:
            raise S7ProtocolError("S7 data too short")
        magic = s7_raw[0]
        resp_type = s7_raw[1]
        if magic != 0x32:
            raise S7ProtocolError("Invalid S7 magic")
        if resp_type in (2, 3):
            # Response with error field
            if len(s7_raw) < 12:
                raise S7ProtocolError("S7 response header too short")
            _, _, _, _, param_len, data_len, error = struct.unpack(
                ">BBHHHHH", s7_raw[:12])
            if error:
                raise S7Error(error)
            return s7_raw[12:12 + param_len + data_len]
        elif resp_type in (1, 7):
            _, _, _, _, param_len, data_len = struct.unpack(
                ">BBHHHH", s7_raw[:10])
            return s7_raw[10:10 + param_len + data_len]
        raise S7ProtocolError(f"Unknown S7 PDU type: {resp_type}")

    def read_szl(self, szl_id: int) -> list[bytes]:
        """Read System Status List (SZL) from PLC."""
        params = struct.pack(">LBBBB",
                             0x00011204, 0x11, 0x44, 0x01, 0x00)
        szl_data_payload = struct.pack(">HH", szl_id, 1)
        data = struct.pack(">BBH", 0xFF, 0x09, len(szl_data_payload)) + szl_data_payload
        resp = self._s7_request(0x07, params, data)

        if len(resp) < 12:
            return []
        # Skip function response header (4 bytes param + return code + transport + len)
        data_start = 4  # after parameter block
        if data_start + 4 > len(resp):
            return []
        _code, _ts, dlen = struct.unpack_from(">BBH", resp, data_start)
        szl_raw = resp[data_start + 4:data_start + 4 + dlen]
        if len(szl_raw) < 8:
            return []
        _, _, elem_size, elem_count = struct.unpack_from(">HHHH", szl_raw, 0)
        entries = []
        offset = 8
        for _ in range(elem_count):
            if offset + elem_size > len(szl_raw):
                break
            entries.append(szl_raw[offset:offset + elem_size])
            offset += elem_size
        return entries

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def brute_tsap(ip: str, port: int, timeout: float,
               src_tsaps: tuple[int, ...] = (0x0100, 0x0200),
               dst_tsaps: tuple[int, ...] = (0x0102, 0x0200, 0x0201)
               ) -> Optional[tuple[int, int]]:
    for src in src_tsaps:
        for dst in dst_tsaps:
            try:
                client = S7Client(ip, port, src, dst, timeout)
                client.connect()
                client.close()
                return (src, dst)
            except (S7ProtocolError, S7Error, socket.error, OSError):
                continue
    return None


def get_s7_identity(ip: str, port: int, src_tsap: int,
                    dst_tsap: int, timeout: float) -> list[str]:
    """Read module and component identification from S7 PLC."""
    client = S7Client(ip, port, src_tsap, dst_tsap, timeout)
    client.connect()
    results = []

    szl_ids = {
        0x0011: {
            "title": "Module Identification",
            "fields": {1: "Module", 6: "Basic Hardware", 7: "Basic Firmware"},
        },
        0x001C: {
            "title": "Component Identification",
            "fields": {
                1: "PLC Name", 2: "Module Name", 3: "Plant ID",
                4: "Copyright", 5: "Serial Number", 7: "Module Type",
                8: "Memory Card Serial", 9: "CPU Profile",
            },
        },
    }

    for szl_id, meta in szl_ids.items():
        try:
            entries = client.read_szl(szl_id)
        except (S7Error, S7ProtocolError):
            continue

        for entry in entries:
            if len(entry) < 4:
                continue
            idx = struct.unpack_from(">H", entry, 0)[0]
            raw = entry[2:]
            label = meta["fields"].get(idx, f"Unknown ({idx})")
            text = raw.decode("ascii", errors="replace").strip("\x00").strip()
            if text:
                results.append(f"{label:25s}: {text}")

    client.close()
    return results


# ---------------------------------------------------------------------------
# Integrated PLC Scanner module
# ---------------------------------------------------------------------------

def expand_targets(spec: str) -> list[str]:
    """Expand a target spec (IP, CIDR, or comma-separated) into IP list."""
    hosts = []
    for part in spec.split(","):
        part = part.strip()
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                hosts.extend(str(h) for h in net.hosts())
            except ValueError:
                hosts.append(part)
        else:
            hosts.append(part)
    return hosts


class PLCScanner(Exploit):
    """PLC discovery scanner supporting Modbus TCP and S7comm."""

    __info__ = {
        "name": "PLC Scanner",
        "description": "Modbus TCP and S7comm PLC discovery and identification scanner",
        "authors": ["Andre Henrique (@mrhenrike)",
                     "Dmitry Efanov / Positive Research (original plcscan)"],
        "references": [
            "https://github.com/yanlinlin82/plcscan",
            "IEC 61158 (Modbus)",
            "Siemens S7comm",
        ],
    }

    target = OptString("", "Target IP, CIDR, or comma-separated list")
    ports = OptString("102,502", "Ports to scan (comma-separated)")
    scan_timeout = OptInteger(5, "Connection timeout per probe (seconds)")
    brute_uid = OptBool(False, "Brute-force all Modbus unit IDs (0-255)")

    def run(self) -> dict:
        targets = expand_targets(self.target)
        ports = [int(p.strip()) for p in self.ports.split(",")]
        timeout = float(self.scan_timeout)
        all_results = {}

        print_status(f"PLC Scanner: {len(targets)} hosts, ports {ports}")

        for host in targets:
            host_results = []
            for port in ports:
                # TCP connectivity check
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout)
                        sock.connect((host, port))
                except (socket.error, OSError):
                    continue

                if port == 102:
                    # S7comm
                    tsap = brute_tsap(host, port, timeout)
                    if tsap:
                        print_success(f"{host}:{port} S7comm (src_tsap=0x{tsap[0]:x}, dst_tsap=0x{tsap[1]:x})")
                        identity = []
                        for attempt in range(2):
                            try:
                                identity = get_s7_identity(host, port, tsap[0], tsap[1], timeout)
                                break
                            except (S7ProtocolError, S7Error, socket.error):
                                continue
                        for line in identity:
                            print_info(f"  {line}")
                        host_results.append({
                            "protocol": "s7comm",
                            "port": port,
                            "tsap": tsap,
                            "identity": identity,
                        })
                elif port == 502:
                    # Modbus
                    uids = list(range(256)) if self.brute_uid else [0, 255]
                    found = False
                    for uid in uids:
                        unit_info = scan_modbus_unit(host, port, uid, timeout)
                        if unit_info:
                            if not found:
                                print_success(f"{host}:{port} Modbus/TCP")
                                found = True
                            print_info(f"  Unit ID: {uid}")
                            for line in unit_info:
                                print_info(f"    {line}")
                            host_results.append({
                                "protocol": "modbus",
                                "port": port,
                                "unit_id": uid,
                                "info": unit_info,
                            })
                else:
                    # Try both
                    unit_info = scan_modbus_unit(host, port, 0, timeout)
                    if unit_info:
                        print_success(f"{host}:{port} Modbus/TCP")
                        host_results.append({
                            "protocol": "modbus", "port": port, "info": unit_info,
                        })
                    else:
                        tsap = brute_tsap(host, port, timeout)
                        if tsap:
                            print_success(f"{host}:{port} S7comm")
                            host_results.append({
                                "protocol": "s7comm", "port": port, "tsap": tsap,
                            })

                if not host_results:
                    print_info(f"{host}:{port} unknown protocol")

            if host_results:
                all_results[host] = host_results

        print_status(f"Scan complete. {len(all_results)} hosts with PLC services found.")
        return all_results


MANIFEST = {
    "name": "plcscan",
    "category": "scanners/ics",
    "protocols": ["modbus", "s7comm"],
    "mitre_ics": ["T0846", "T0888"],
    "source": "https://github.com/yanlinlin82/plcscan",
    "license": "BSD",
}
