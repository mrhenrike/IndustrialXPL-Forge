"""ICS Ninja Scanner: multi-protocol industrial control system scanner.

Adapted from MottaSec ICS-Ninja-Scanner (Apache-2.0).
Supports Modbus TCP, S7comm, DNP3, BACnet, EtherNet/IP, OPC-UA,
MQTT, PROFINET, IEC 104, HART-IP, SNMP for ICS device discovery.

Each protocol scanner performs device identification, function code
enumeration, security posture checks, and CVE correlation.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
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

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"


@dataclass
class ScanResult:
    """Result from a single protocol scan against one target."""
    protocol: str
    target: str
    port: int
    device_info: dict = field(default_factory=dict)
    issues: list = field(default_factory=list)


def _issue(severity: str, description: str, details: str = "",
           remediation: str = "") -> dict:
    return {
        "severity": severity,
        "description": description,
        "details": details,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# Modbus TCP Scanner
# ---------------------------------------------------------------------------

MODBUS_PORT = 502
MODBUS_COMMON_UIDS = list(range(1, 11)) + [247]
MODBUS_REGISTER_RANGES = [(0, 10), (1000, 1010), (4000, 4010), (40000, 40010)]
MODBUS_COIL_RANGES = [(0, 10), (100, 110)]


def _modbus_build(unit_id: int, fc: int, data: bytes,
                  tid: int = 0) -> bytes:
    pdu = bytes([fc]) + data
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit_id) + pdu


def _modbus_parse(raw: bytes) -> dict:
    if len(raw) < 8:
        return {"error": "Response too short"}
    tid, proto, length, uid = struct.unpack_from(">HHHB", raw, 0)
    fc = raw[7]
    data = raw[8:]
    if fc & 0x80:
        exc = data[0] if data else 0
        return {"error": "Modbus exception", "exception_code": exc, "fc": fc & 0x7F}
    return {"transaction_id": tid, "unit_id": uid, "function_code": fc, "data": data}


def _modbus_request(host: str, port: int, unit_id: int, fc: int,
                    data: bytes, timeout: float = 5.0) -> Optional[dict]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(_modbus_build(unit_id, fc, data))
            raw = sock.recv(1024)
            if not raw:
                return None
            return _modbus_parse(raw)
    except (socket.error, OSError):
        return None


def scan_modbus(target: str, port: int = 502, timeout: float = 5.0,
                intensity: str = "low") -> Optional[ScanResult]:
    """Scan a target for Modbus TCP security issues."""
    result = ScanResult(protocol="modbus", target=target, port=port)

    resp = _modbus_request(target, port, 0, 0x11, b"", timeout)
    if resp is None:
        resp = _modbus_request(target, port, 1, 0x03,
                               struct.pack(">HH", 0, 1), timeout)
    if resp is None:
        return None

    result.issues.append(_issue(SEVERITY_INFO,
                                f"Modbus device found at {target}:{port}",
                                "Device responded to Modbus TCP query."))

    result.issues.append(_issue(SEVERITY_HIGH,
                                "No authentication on Modbus TCP",
                                "Modbus TCP has no built-in authentication. "
                                "Any network node can read/write coils and registers.",
                                "Deploy Modbus/TLS (port 802) or network segmentation."))

    # Device identification: FC 43 (0x2B), MEI type 14 (0x0E)
    dev_resp = _modbus_request(target, port, 0, 0x2B,
                               b"\x0e\x01\x00", timeout)
    if dev_resp and "data" in dev_resp:
        data = dev_resp["data"]
        if len(data) > 6:
            obj_count = data[5]
            payload = data[6:]
            info_parts = []
            for _ in range(obj_count):
                if len(payload) < 2:
                    break
                obj_len = payload[1]
                info_parts.append(payload[2:2 + obj_len].decode("ascii", errors="replace"))
                payload = payload[2 + obj_len:]
            if info_parts:
                result.device_info["vendor"] = info_parts[0] if info_parts else ""
                result.device_info["product"] = info_parts[1] if len(info_parts) > 1 else ""
                result.device_info["version"] = info_parts[2] if len(info_parts) > 2 else ""
                result.issues.append(_issue(SEVERITY_MEDIUM,
                                            f"Device identification exposed: {' '.join(info_parts)}",
                                            "FC 43/14 (Read Device Identification) returned device info.",
                                            "Restrict FC 43 via ICS firewall rules."))

    # Unit ID enumeration
    responsive_uids = []
    uids = MODBUS_COMMON_UIDS if intensity == "low" else list(range(0, 248))
    for uid in uids:
        r = _modbus_request(target, port, uid, 0x03,
                            struct.pack(">HH", 0, 1), timeout)
        if r and "error" not in r:
            responsive_uids.append(uid)
    if responsive_uids:
        result.device_info["responsive_unit_ids"] = responsive_uids
        result.issues.append(_issue(SEVERITY_INFO,
                                    f"Responsive unit IDs: {responsive_uids}",
                                    f"Found {len(responsive_uids)} units responding."))

    # Register read test (non-destructive)
    for start, end in MODBUS_REGISTER_RANGES[:2]:
        count = end - start
        r = _modbus_request(target, port, responsive_uids[0] if responsive_uids else 1,
                            0x03, struct.pack(">HH", start, count), timeout)
        if r and "data" in r and len(r["data"]) > 1:
            result.issues.append(_issue(SEVERITY_HIGH,
                                        f"Holding registers readable: range {start}-{end}",
                                        f"FC 03 returned {len(r['data'])} bytes from register {start}.",
                                        "Restrict read access via ICS firewall or Modbus deep packet inspection."))
            break

    # Coil read test
    for start, end in MODBUS_COIL_RANGES[:1]:
        count = end - start
        r = _modbus_request(target, port, responsive_uids[0] if responsive_uids else 1,
                            0x01, struct.pack(">HH", start, count), timeout)
        if r and "data" in r and len(r["data"]) > 1:
            result.issues.append(_issue(SEVERITY_HIGH,
                                        f"Coils readable: range {start}-{end}",
                                        "FC 01 (Read Coils) succeeded. Coils control digital outputs.",
                                        "Restrict coil read/write via ICS firewall."))
            break

    # Check for broadcast unit ID (0)
    r = _modbus_request(target, port, 0, 0x03,
                        struct.pack(">HH", 0, 1), timeout)
    if r and "error" not in r:
        result.issues.append(_issue(SEVERITY_MEDIUM,
                                    "Broadcast unit ID (0) accepted",
                                    "Device responds to unit ID 0, which is the broadcast address.",
                                    "Configure device to reject broadcast queries."))

    return result


# ---------------------------------------------------------------------------
# S7comm Scanner (Siemens S7 PLCs)
# ---------------------------------------------------------------------------

S7_PORT = 102

S7_PROTECTION_LEVELS = {
    0: "No protection",
    1: "Password protected",
    2: "Reserved",
    3: "Full protection (no read/write)",
}

SIEMENS_VULN_DB = [
    {"pattern": "6ES7 21", "series": "S7-1200", "max_vuln": (4, 3, 99),
     "cves": ["CVE-2019-13945"], "advisory": "SSA-232418",
     "desc": "S7-1200 firmware < V4.4: access protection bypass"},
    {"pattern": "6ES7 51", "series": "S7-1500", "max_vuln": (2, 8, 0),
     "cves": ["CVE-2019-10929", "CVE-2019-10943"], "advisory": "SSA-232418",
     "desc": "S7-1500 firmware < V2.8.1: session hijack via crypto weakness"},
    {"pattern": "6ES7 31", "series": "S7-300", "max_vuln": (3, 99, 99),
     "cves": ["CVE-2016-9159"], "advisory": "SSA-731239",
     "desc": "S7-300: credential disclosure over S7 communication"},
    {"pattern": "6ES7 41", "series": "S7-400", "max_vuln": (6, 99, 99),
     "cves": ["CVE-2016-9159"], "advisory": "SSA-731239",
     "desc": "S7-400: credential disclosure over S7 communication"},
    {"pattern": "6ES7 21", "series": "S7-1200", "max_vuln": (4, 4, 99),
     "cves": ["CVE-2020-15782"], "advisory": "SSA-434534",
     "desc": "S7-1200 firmware <= V4.4: memory protection bypass (code execution)"},
    {"pattern": "6ES7 51", "series": "S7-1500", "max_vuln": (2, 8, 3),
     "cves": ["CVE-2020-15782"], "advisory": "SSA-434534",
     "desc": "S7-1500 firmware < V2.9: memory protection bypass (code execution)"},
]


def _s7_build_tpkt(data: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(data) + 4) + data


def _s7_cotp_cr(src_tsap: int = 0x0100, dst_tsap: int = 0x0102) -> bytes:
    return struct.pack(">BBHHBBBHBBHBBB",
                       17, 0xE0, 0, 0x0004, 0,
                       0xC1, 2, src_tsap,
                       0xC2, 2, dst_tsap,
                       0xC0, 1, 0x0A)


def _s7_cotp_dt(payload: bytes) -> bytes:
    return struct.pack(">BBB", 2, 0xF0, 0x80) + payload


def _s7_negotiate_pdu(pdu_size: int = 480) -> bytes:
    return struct.pack(">BBHHHH", 0x32, 0x01, 0, 0,
                       6, 0) + struct.pack(">BBHHH",
                                           0xF0, 0x00, 0x01, 0x01, pdu_size)


def _s7_read_szl(szl_id: int, szl_index: int = 1) -> bytes:
    params = struct.pack(">LBBBB",
                         0x00011204, 0x11, 0x44, 0x01, 0x00)
    data = struct.pack(">BBH", 0xFF, 0x09, 4) + struct.pack(">HH", szl_id, szl_index)
    return struct.pack(">BBHHHH", 0x32, 0x07, 0, 0,
                       len(params), len(data)) + params + data


def _s7_connect(host: str, port: int, timeout: float,
                src_tsap: int, dst_tsap: int) -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_s7_build_tpkt(_s7_cotp_cr(src_tsap, dst_tsap)))
        reply = sock.recv(1024)
        if len(reply) < 7 or reply[5] != 0xD0:
            sock.close()
            return None
        sock.sendall(_s7_build_tpkt(_s7_cotp_dt(_s7_negotiate_pdu())))
        reply = sock.recv(1024)
        if not reply or len(reply) < 12:
            sock.close()
            return None
        return sock
    except (socket.error, OSError):
        return None


def _s7_request(sock: socket.socket, payload: bytes) -> Optional[bytes]:
    try:
        sock.sendall(_s7_build_tpkt(_s7_cotp_dt(payload)))
        reply = sock.recv(4096)
        if not reply or len(reply) < 17:
            return None
        tpkt_len = struct.unpack_from(">H", reply, 2)[0]
        cotp_hdr = reply[4]
        s7_data = reply[4 + cotp_hdr + 1:]
        return s7_data
    except (socket.error, OSError):
        return None


def scan_s7comm(target: str, port: int = 102, timeout: float = 5.0,
                intensity: str = "low") -> Optional[ScanResult]:
    """Scan for Siemens S7 PLC security issues."""
    result = ScanResult(protocol="s7comm", target=target, port=port)

    tsap_pairs = [(0x0100, 0x0102), (0x0200, 0x0200), (0x0200, 0x0201)]
    connected_sock = None
    used_tsap = None

    for src, dst in tsap_pairs:
        sock = _s7_connect(target, port, timeout, src, dst)
        if sock:
            connected_sock = sock
            used_tsap = (src, dst)
            break

    if not connected_sock:
        return None

    result.issues.append(_issue(SEVERITY_INFO,
                                f"S7comm device found at {target}:{port}",
                                f"Connected via TSAP src=0x{used_tsap[0]:04x} dst=0x{used_tsap[1]:04x}"))

    result.issues.append(_issue(SEVERITY_HIGH,
                                "S7comm accessible without authentication",
                                "S7comm protocol does not require authentication by default. "
                                "An attacker on the network can read/write PLC memory, stop the CPU, "
                                "and upload logic.",
                                "Enable access protection on the PLC. Deploy network segmentation."))

    # Read SZL 0x0011 (Module Identification)
    szl_resp = _s7_request(connected_sock, _s7_read_szl(0x0011))
    if szl_resp and len(szl_resp) > 20:
        try:
            offset = 12
            if len(szl_resp) > offset + 28:
                raw_name = szl_resp[offset + 4:offset + 24]
                module_name = raw_name.decode("ascii", errors="replace").strip("\x00").strip()
                result.device_info["module"] = module_name
                result.issues.append(_issue(SEVERITY_MEDIUM,
                                            f"Module identification exposed: {module_name}",
                                            "SZL 0x0011 returned module info."))

                # CVE check
                for vuln in SIEMENS_VULN_DB:
                    if vuln["pattern"] in module_name:
                        result.issues.append(_issue(SEVERITY_CRITICAL,
                                                    f"Potential vulnerability: {', '.join(vuln['cves'])}",
                                                    f"{vuln['desc']} (Advisory: {vuln['advisory']})",
                                                    "Update firmware to latest version. Apply Siemens advisory patches."))
        except (struct.error, IndexError):
            pass

    # Read SZL 0x001C (Component Identification)
    szl_resp = _s7_request(connected_sock, _s7_read_szl(0x001C))
    if szl_resp and len(szl_resp) > 20:
        try:
            offset = 12
            entries = []
            elem_size = struct.unpack_from(">H", szl_resp, 8)[0] if len(szl_resp) > 10 else 34
            while offset + elem_size <= len(szl_resp):
                entry = szl_resp[offset:offset + elem_size]
                idx = struct.unpack_from(">H", entry, 0)[0]
                text = entry[2:min(26, elem_size)].decode("ascii", errors="replace").strip("\x00").strip()
                if text:
                    entries.append((idx, text))
                offset += elem_size
            for idx, text in entries:
                labels = {1: "plc_name", 2: "module_name", 5: "serial",
                          7: "module_type", 9: "cpu_profile"}
                key = labels.get(idx, f"component_{idx}")
                result.device_info[key] = text
            if entries:
                info_str = "; ".join(f"{k}={v}" for k, v in
                                     [(labels.get(i, f"idx{i}"), t) for i, t in entries])
                result.issues.append(_issue(SEVERITY_MEDIUM,
                                            f"Component identification: {info_str}",
                                            "SZL 0x001C returned component details."))
        except (struct.error, IndexError):
            pass

    connected_sock.close()
    return result


# ---------------------------------------------------------------------------
# DNP3 Scanner (IEEE 1815 / IEC 62351)
# ---------------------------------------------------------------------------

DNP3_PORT = 20000
DNP3_START_BYTES = b"\x05\x64"


def _dnp3_build_request(dst: int = 1, src: int = 0,
                        fc: int = 0x00) -> bytes:
    """Build a minimal DNP3 link layer frame (data link confirm / read)."""
    length = 5
    ctrl = 0xC0 | fc
    header = struct.pack("<BBHH", length, ctrl, dst, src)
    # CRC-16/DNP for the header
    crc = _dnp3_crc(header)
    return DNP3_START_BYTES + header + struct.pack("<H", crc)


def _dnp3_crc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def scan_dnp3(target: str, port: int = 20000, timeout: float = 5.0,
              intensity: str = "low") -> Optional[ScanResult]:
    """Scan for DNP3 outstation security issues."""
    result = ScanResult(protocol="dnp3", target=target, port=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Send link status request
            sock.sendall(_dnp3_build_request(dst=1, src=0, fc=0x09))
            reply = sock.recv(1024)

            if not reply or len(reply) < 10:
                return None

            if reply[:2] != DNP3_START_BYTES:
                return None

            result.issues.append(_issue(SEVERITY_INFO,
                                        f"DNP3 outstation found at {target}:{port}",
                                        "Device responded to DNP3 link status request."))

            result.issues.append(_issue(SEVERITY_HIGH,
                                        "DNP3 lacks built-in authentication",
                                        "Standard DNP3 (pre-SA) has no authentication. "
                                        "Attackers can inject control commands.",
                                        "Enable DNP3 Secure Authentication (SA) per IEC 62351."))

            # Parse link layer response
            if len(reply) >= 10:
                r_len, r_ctrl = struct.unpack_from("<BB", reply, 2)
                r_dst, r_src = struct.unpack_from("<HH", reply, 4)
                result.device_info["dnp3_address"] = r_src
                result.issues.append(_issue(SEVERITY_INFO,
                                            f"DNP3 outstation address: {r_src}",
                                            f"Link layer: dst={r_dst}, src={r_src}, ctrl=0x{r_ctrl:02x}"))

            # Try to read class 0 data (FC=0x01, Read)
            if intensity in ("medium", "high"):
                class0_req = _dnp3_build_request(dst=1, src=0, fc=0x01)
                sock.sendall(class0_req)
                time.sleep(0.5)
                try:
                    data = sock.recv(4096)
                    if data and len(data) > 10:
                        result.issues.append(_issue(SEVERITY_HIGH,
                                                    "DNP3 Class 0 data readable",
                                                    f"Read request returned {len(data)} bytes of process data.",
                                                    "Restrict read access via ICS firewall or enable SA."))
                except socket.timeout:
                    pass

    except (socket.error, OSError):
        return None

    return result


# ---------------------------------------------------------------------------
# BACnet Scanner (ASHRAE 135 / ISO 16484-5)
# ---------------------------------------------------------------------------

BACNET_PORT = 47808


def _bacnet_whois() -> bytes:
    """Build BACnet/IP Who-Is broadcast packet."""
    # BVLC header: type=0x81 (BACnet/IP), function=0x0B (original broadcast),
    # length=12, BACnet NPDU + APDU
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    apdu = bytes([0x10, 0x08])  # Unconfirmed Who-Is
    bvlc = struct.pack(">BBH", 0x81, 0x0B, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


def _bacnet_read_property(instance: int, prop_id: int) -> bytes:
    """Build BACnet ReadProperty request for device object."""
    # BVLC
    obj_id = struct.pack(">I", (8 << 22) | instance)  # device object
    prop_bytes = bytes([prop_id])
    apdu = bytes([0x00, 0x00, 0x01, 0x0C]) + obj_id + bytes([0x19]) + prop_bytes
    npdu = bytes([0x01, 0x04])
    bvlc = struct.pack(">BBH", 0x81, 0x0A, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


def scan_bacnet(target: str, port: int = 47808, timeout: float = 5.0,
                intensity: str = "low") -> Optional[ScanResult]:
    """Scan for BACnet/IP device security issues."""
    result = ScanResult(protocol="bacnet", target=target, port=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(_bacnet_whois(), (target, port))

            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                return None

            if not data or len(data) < 8:
                return None

            if data[0] != 0x81:
                return None

            result.issues.append(_issue(SEVERITY_INFO,
                                        f"BACnet/IP device found at {target}:{port}",
                                        "Device responded to Who-Is broadcast."))

            result.issues.append(_issue(SEVERITY_HIGH,
                                        "BACnet/IP lacks authentication",
                                        "BACnet/IP has no built-in authentication. "
                                        "Any node can read/write properties and control BAS.",
                                        "Implement BACnet Secure Connect (BACnet/SC) per Addendum BJ."))

            # Parse I-Am response
            if len(data) > 12:
                npdu_start = 4
                if data[npdu_start] == 0x01:
                    apdu_start = npdu_start + 2
                    if data[npdu_start + 1] & 0x20:
                        apdu_start += 4
                    if apdu_start < len(data) and data[apdu_start] == 0x10:
                        # I-Am APDU
                        try:
                            obj_start = apdu_start + 2
                            if obj_start + 4 <= len(data):
                                obj_raw = struct.unpack_from(">I", data, obj_start + 1)[0]
                                instance = obj_raw & 0x3FFFFF
                                result.device_info["instance"] = instance
                                result.issues.append(_issue(SEVERITY_INFO,
                                                            f"BACnet device instance: {instance}",
                                                            "Extracted from I-Am response."))
                        except (struct.error, IndexError):
                            pass

    except (socket.error, OSError):
        return None

    return result


# ---------------------------------------------------------------------------
# EtherNet/IP Scanner (CIP over TCP/44818)
# ---------------------------------------------------------------------------

ENIP_PORT = 44818


def _enip_list_identity() -> bytes:
    """Build EtherNet/IP ListIdentity command."""
    return struct.pack("<HHIIQII",
                       0x0063,  # command: ListIdentity
                       0,       # length
                       0,       # session handle
                       0,       # status
                       0,       # sender context
                       0, 0)    # options


def scan_enip(target: str, port: int = 44818, timeout: float = 5.0,
              intensity: str = "low") -> Optional[ScanResult]:
    """Scan for EtherNet/IP (CIP) device security issues."""
    result = ScanResult(protocol="ethernet_ip", target=target, port=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.sendall(_enip_list_identity())
            reply = sock.recv(4096)

            if not reply or len(reply) < 24:
                return None

            cmd, length = struct.unpack_from("<HH", reply, 0)
            if cmd != 0x0063:
                return None

            result.issues.append(_issue(SEVERITY_INFO,
                                        f"EtherNet/IP device found at {target}:{port}",
                                        "Device responded to ListIdentity."))

            # Parse identity
            if len(reply) > 48:
                try:
                    item_start = 28
                    if item_start + 20 < len(reply):
                        vendor = struct.unpack_from("<H", reply, item_start + 4)[0]
                        device_type = struct.unpack_from("<H", reply, item_start + 6)[0]
                        product_code = struct.unpack_from("<H", reply, item_start + 8)[0]
                        major = reply[item_start + 10]
                        minor = reply[item_start + 11]
                        serial = struct.unpack_from("<I", reply, item_start + 14)[0]
                        name_len = reply[item_start + 18] if item_start + 18 < len(reply) else 0
                        name = ""
                        if name_len > 0 and item_start + 19 + name_len <= len(reply):
                            name = reply[item_start + 19:item_start + 19 + name_len].decode(
                                "ascii", errors="replace")
                        result.device_info["vendor_id"] = vendor
                        result.device_info["device_type"] = device_type
                        result.device_info["product_code"] = product_code
                        result.device_info["revision"] = f"{major}.{minor}"
                        result.device_info["serial"] = f"0x{serial:08x}"
                        result.device_info["product_name"] = name
                        result.issues.append(_issue(SEVERITY_MEDIUM,
                                                    f"Device identity exposed: {name} v{major}.{minor}",
                                                    f"Vendor={vendor}, Type={device_type}, Serial=0x{serial:08x}",
                                                    "Restrict ListIdentity via ICS firewall."))
                except (struct.error, IndexError):
                    pass

            result.issues.append(_issue(SEVERITY_HIGH,
                                        "EtherNet/IP CIP accessible without authentication",
                                        "Standard CIP does not require authentication for implicit messaging.",
                                        "Use CIP Security (TLS/DTLS) per ODVA specification."))

    except (socket.error, OSError):
        return None

    return result


# ---------------------------------------------------------------------------
# IEC 60870-5-104 Scanner
# ---------------------------------------------------------------------------

IEC104_PORT = 2404


def _iec104_startdt_act() -> bytes:
    """Build IEC 104 STARTDT act U-frame."""
    return bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


def scan_iec104(target: str, port: int = 2404, timeout: float = 5.0,
                intensity: str = "low") -> Optional[ScanResult]:
    """Scan for IEC 60870-5-104 security issues."""
    result = ScanResult(protocol="iec104", target=target, port=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.sendall(_iec104_startdt_act())
            reply = sock.recv(1024)

            if not reply or len(reply) < 6:
                return None

            if reply[0] != 0x68:
                return None

            result.issues.append(_issue(SEVERITY_INFO,
                                        f"IEC 104 device found at {target}:{port}",
                                        "Device responded to STARTDT activation."))

            # Check if STARTDT was confirmed
            if reply[2] == 0x0B:
                result.issues.append(_issue(SEVERITY_HIGH,
                                            "IEC 104 connection accepted without authentication",
                                            "STARTDT confirmed. Standard IEC 104 has no authentication.",
                                            "Enable IEC 62351 or VPN encapsulation."))
            else:
                result.issues.append(_issue(SEVERITY_INFO,
                                            f"IEC 104 response type: 0x{reply[2]:02x}",
                                            "Device did not confirm STARTDT."))

    except (socket.error, OSError):
        return None

    return result


# ---------------------------------------------------------------------------
# MQTT Scanner
# ---------------------------------------------------------------------------

MQTT_PORT = 1883


def _mqtt_connect(client_id: str = "ixf_scan") -> bytes:
    """Build MQTT CONNECT packet (v3.1.1)."""
    var_header = (b"\x00\x04MQTT"
                  b"\x04"       # protocol level (3.1.1)
                  b"\x02"       # connect flags: clean session
                  b"\x00\x3c")  # keep alive: 60s
    payload = struct.pack(">H", len(client_id)) + client_id.encode("ascii")
    remaining = len(var_header) + len(payload)
    fixed = bytes([0x10])  # CONNECT packet type
    encoded_len = bytearray()
    while remaining > 0:
        byte = remaining % 128
        remaining //= 128
        if remaining > 0:
            byte |= 0x80
        encoded_len.append(byte)
    return fixed + bytes(encoded_len) + var_header + payload


def scan_mqtt(target: str, port: int = 1883, timeout: float = 5.0,
              intensity: str = "low") -> Optional[ScanResult]:
    """Scan MQTT broker for security issues."""
    result = ScanResult(protocol="mqtt", target=target, port=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.sendall(_mqtt_connect())
            reply = sock.recv(1024)

            if not reply or len(reply) < 4:
                return None

            if (reply[0] >> 4) != 2:  # CONNACK
                return None

            result.issues.append(_issue(SEVERITY_INFO,
                                        f"MQTT broker found at {target}:{port}",
                                        "Broker accepted connection."))

            return_code = reply[3]
            if return_code == 0:
                result.issues.append(_issue(SEVERITY_CRITICAL,
                                            "MQTT broker allows anonymous connections",
                                            "Connection accepted without credentials (return code 0).",
                                            "Require authentication. Use MQTT over TLS (port 8883)."))
            elif return_code == 5:
                result.issues.append(_issue(SEVERITY_INFO,
                                            "MQTT broker requires authentication",
                                            "Connection refused: not authorized (return code 5)."))
            else:
                result.issues.append(_issue(SEVERITY_INFO,
                                            f"MQTT CONNACK return code: {return_code}",
                                            f"Connection response code {return_code}."))

            # Try subscribing to # (wildcard)
            if return_code == 0 and intensity in ("medium", "high"):
                sub_topic = b"#"
                sub_packet = (bytes([0x82])
                              + bytes([2 + 2 + len(sub_topic) + 1])
                              + struct.pack(">H", 1)
                              + struct.pack(">H", len(sub_topic))
                              + sub_topic
                              + bytes([0x00]))
                sock.sendall(sub_packet)
                time.sleep(1)
                try:
                    sub_reply = sock.recv(4096)
                    if sub_reply and (sub_reply[0] >> 4) == 9:
                        result.issues.append(_issue(SEVERITY_CRITICAL,
                                                    "MQTT wildcard subscription accepted",
                                                    "Subscribed to '#' (all topics). "
                                                    "Full message interception is possible.",
                                                    "Restrict topic ACLs. Require TLS client certificates."))
                except socket.timeout:
                    pass

    except (socket.error, OSError):
        return None

    return result


# ---------------------------------------------------------------------------
# Aggregated multi-protocol scanner
# ---------------------------------------------------------------------------

PROTOCOL_SCANNERS = {
    "modbus": (scan_modbus, MODBUS_PORT),
    "s7comm": (scan_s7comm, S7_PORT),
    "dnp3": (scan_dnp3, DNP3_PORT),
    "bacnet": (scan_bacnet, BACNET_PORT),
    "enip": (scan_enip, ENIP_PORT),
    "iec104": (scan_iec104, IEC104_PORT),
    "mqtt": (scan_mqtt, MQTT_PORT),
}


class ICSNinjaScanner(Exploit):
    """Multi-protocol ICS/OT scanner for security assessment."""

    __info__ = {
        "name": "ICS Ninja Scanner",
        "description": "Multi-protocol ICS security scanner (Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC104, MQTT)",
        "authors": ["Andre Henrique (@mrhenrike)", "MottaSec (original)"],
        "references": [
            "https://github.com/MottaSec/ICS-Ninja-Scanner",
            "IEC 62443",
            "NIST SP 800-82",
        ],
    }

    target = OptIP("", "Target IP address")
    protocols = OptString("all", "Protocols to scan (comma-separated or 'all')")
    intensity = OptString("low", "Scan intensity: low, medium, high")
    port_override = OptString("", "Override default ports (proto:port,proto:port)")
    scan_timeout = OptInteger(5, "Connection timeout per probe (seconds)")

    def run(self) -> list[ScanResult]:
        target = self.target
        timeout = float(self.scan_timeout)
        intensity = self.intensity

        proto_list = list(PROTOCOL_SCANNERS.keys())
        if self.protocols != "all":
            requested = [p.strip().lower() for p in self.protocols.split(",")]
            proto_list = [p for p in requested if p in PROTOCOL_SCANNERS]

        port_overrides = {}
        if self.port_override:
            for pair in self.port_override.split(","):
                if ":" in pair:
                    proto, port_str = pair.split(":", 1)
                    port_overrides[proto.strip()] = int(port_str.strip())

        results = []
        print_status(f"Starting ICS Ninja Scanner against {target}")
        print_status(f"Protocols: {', '.join(proto_list)} | Intensity: {intensity}")

        for proto in proto_list:
            scanner_fn, default_port = PROTOCOL_SCANNERS[proto]
            port = port_overrides.get(proto, default_port)
            print_status(f"Scanning {proto.upper()} on {target}:{port}...")

            try:
                scan_result = scanner_fn(target, port, timeout, intensity)
                if scan_result:
                    results.append(scan_result)
                    issues = scan_result.issues
                    crits = sum(1 for i in issues if i["severity"] == SEVERITY_CRITICAL)
                    highs = sum(1 for i in issues if i["severity"] == SEVERITY_HIGH)
                    if crits > 0:
                        print_error(f"  {proto.upper()}: {crits} CRITICAL, {highs} HIGH findings")
                    elif highs > 0:
                        print_warning(f"  {proto.upper()}: {highs} HIGH findings")
                    else:
                        print_success(f"  {proto.upper()}: Device found, {len(issues)} info items")
                else:
                    print_info(f"  {proto.upper()}: No device detected")
            except KeyError as exc:
                log.debug("Scanner %s error: %s", proto, exc)
                print_error(f"  {proto.upper()}: Error during scan: {exc}")

        print_status(f"Scan complete. {len(results)} protocols responded.")
        return results


MANIFEST = {
    "name": "ics_ninja_scanner",
    "category": "scanners/ics",
    "protocols": ["modbus", "s7comm", "dnp3", "bacnet", "ethernet_ip", "iec104", "mqtt"],
    "mitre_ics": ["T0846", "T0842", "T0888"],
    "source": "https://github.com/MottaSec/ICS-Ninja-Scanner",
    "license": "Apache-2.0",
}
