"""
industrialxpl/protocols/s7comm.py - Native S7comm protocol stack.

Implements the Siemens S7 Communication Protocol as used by S7-300/400/1200/1500 PLCs.
Pure-Python using struct + socket via CotpConnection - no Scapy, no python-snap7.

Protocol reference:
    - Reverse-engineered S7comm documentation (Wireshark community)
    - MITRE ATT&CK ICS: T0845 Program Upload, T0843 POU Discovery, T0846 Remote Discovery

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

S7_PROTOCOL_ID = 0x32

S7_PDU_TYPE: Dict[int, str] = {
    0x01: "Job",
    0x02: "Ack",
    0x03: "AckData",
    0x07: "UserData",
}

S7_FUNCTION: Dict[int, str] = {
    0x00: "CPUServices",
    0x04: "ReadVar",
    0x05: "WriteVar",
    0x1A: "RequestDownload",
    0x1B: "DownloadBlock",
    0x1C: "DownloadEnded",
    0x1D: "StartUpload",
    0x1E: "Upload",
    0x1F: "EndUpload",
    0x28: "PIService",
    0x29: "PLCStop",
    0xF0: "SetupComm",
}

S7_AREA: Dict[int, str] = {
    0x80: "P",       # Direct peripheral access
    0x81: "I",       # Inputs
    0x82: "Q",       # Outputs
    0x83: "M",       # Merkers/Flags
    0x84: "DB",      # Data blocks
    0x85: "DI",      # Instance data blocks
    0x1C: "Counter",
    0x1D: "Timer",
}

# Area value for area name
AREA_CODE: Dict[str, int] = {v: k for k, v in S7_AREA.items()}

S7_TRANSPORT_SIZE: Dict[str, int] = {
    "BIT": 0x01,
    "BYTE": 0x02,
    "CHAR": 0x03,
    "WORD": 0x04,
    "INT": 0x05,
    "DWORD": 0x06,
    "DINT": 0x07,
    "REAL": 0x08,
}

S7_ERROR_CLASS: Dict[int, str] = {
    0x00: "No Error",
    0xD6: "Authentication Error",
}

# SZL (System Status List) IDs
SZL_MODULE_ID = 0x0011       # Module identification
SZL_COMPONENT_ID = 0x001C    # Component identification
SZL_CPU_INFO = 0x0131        # CPU characteristics

# S7comm setup PDU - negotiate PDU size 480 bytes
S7_SETUP_COMM = bytes.fromhex(
    "320100000000000800000000f0000001000101e0"
)

# S7 Read SZL request template (SZL 0x0011 - Module ID)
_SZL_READ_HEADER = bytes.fromhex("320700000000000c00020001120411")


@dataclass
class S7Header:
    """Parsed S7comm PDU header."""
    pdu_type: int
    req_id: int = 0
    param_length: int = 0
    data_length: int = 0
    error_class: int = 0
    error_code: int = 0


@dataclass
class S7Response:
    """Result from an S7comm operation."""
    success: bool
    function: str = ""
    data: bytes = field(default_factory=bytes)
    error_class: int = 0
    error_code: int = 0
    error_msg: str = ""
    parsed: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_s7_header(
    pdu_type: int,
    func_code: int,
    req_id: int = 0,
    param: bytes = b"",
    data: bytes = b"",
) -> bytes:
    """Build S7comm PDU header + parameter + data.

    S7 PDU structure:
        protocol_id(1) + pdu_type(1) + reserved(2) + req_id(2) +
        param_len(2) + data_len(2) [+ error_class(1) + error_code(1) for AckData] +
        parameter + data
    """
    # For Job (0x01): 10 bytes header
    header = struct.pack(
        ">BBHHHH",
        S7_PROTOCOL_ID,  # 0x32
        pdu_type,
        0x0000,          # reserved
        req_id,
        len(param),
        len(data),
    )
    return header + param + data


def build_setup_comm() -> bytes:
    """Build S7 Communication Setup PDU (negotiate PDU size)."""
    return S7_SETUP_COMM


def build_read_szl(szl_id: int, szl_index: int = 0x0001) -> bytes:
    """Build S7 Read SZL (System Status List) request.

    Args:
        szl_id: SZL ID to read (e.g. 0x0011 for module info).
        szl_index: SZL index (usually 0x0001 or 0x0000).
    """
    # UserData header + SZL read sub-function
    ud_param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    szl_data = struct.pack(">HH", szl_id, szl_index)
    # Length prefix for data section
    data_section = struct.pack(">HH", len(szl_data) + 4, len(szl_data)) + szl_data
    header = struct.pack(">BBHHHH", 0x32, 0x07, 0, 0x0500, len(ud_param), len(data_section))
    return header + ud_param + data_section


def build_cpu_stop() -> bytes:
    """Build S7 PLC Stop request (FC=0x29)."""
    param = bytes([0x29, 0x00, 0x00, 0x00, 0x00, 0x09]) + b"P_PROGRAM"
    return build_s7_header(0x01, 0x29, param=param)


def build_cpu_start() -> bytes:
    """Build S7 PLC Start (hot restart) via PI-Service."""
    # PI-Service _INSE (hot start)
    pi_data = b"\x00\x00\x00\x00\x00\x00\xfd\x00\x00\x00\x07_INSE"
    param = struct.pack(">B", 0x28) + pi_data
    return build_s7_header(0x01, 0x28, param=param)


def build_read_area(
    area: int,
    db_number: int,
    start: int,
    length: int,
    transport_size: int = 0x04,  # WORD
) -> bytes:
    """Build S7 Read Variable request (FC04).

    Args:
        area: Area code (e.g. 0x84 for DB).
        db_number: DB number (0 for non-DB areas).
        start: Bit start address.
        length: Number of elements.
        transport_size: Data type (0x04=WORD, 0x02=BYTE, etc.).
    """
    # Item descriptor: transport_size(1) length(2) db_number(2) area(1) start_addr(3)
    item = struct.pack(
        ">BBHBBHB",
        0x12,            # variable spec
        0x0A,            # length of item
        0x10,            # addressing mode (any)
        transport_size,
        0,               # length high
    )
    # start address as 3 bytes big-endian
    item += struct.pack(">B", (start >> 16) & 0xFF)
    item += struct.pack(">H", start & 0xFFFF)
    item += struct.pack(">HB", db_number, area)

    # Rebuild properly
    item = bytes([0x12, 0x0A, 0x10, transport_size])
    item += struct.pack(">H", length)
    item += struct.pack(">H", db_number)
    item += struct.pack(">B", area)
    # start in bits (for byte access: byte_offset * 8)
    start_bits = start
    item += bytes([(start_bits >> 16) & 0xFF, (start_bits >> 8) & 0xFF, start_bits & 0xFF])

    param = bytes([0x04, 0x01]) + item  # function 0x04 + item count 0x01
    return build_s7_header(0x01, 0x04, param=param)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def parse_s7_header(data: bytes) -> Optional[S7Header]:
    """Parse S7comm PDU header from raw bytes."""
    if len(data) < 10:
        return None
    if data[0] != S7_PROTOCOL_ID:
        return None
    pdu_type = data[1]
    req_id = struct.unpack_from(">H", data, 4)[0]
    param_len = struct.unpack_from(">H", data, 6)[0]
    data_len = struct.unpack_from(">H", data, 8)[0]
    error_class = 0
    error_code = 0
    if pdu_type == 0x03 and len(data) >= 12:  # AckData has error bytes
        error_class = data[10]
        error_code = data[11]
    return S7Header(
        pdu_type=pdu_type,
        req_id=req_id,
        param_length=param_len,
        data_length=data_len,
        error_class=error_class,
        error_code=error_code,
    )


def parse_szl_response(raw: bytes) -> Dict[str, str]:
    """Extract readable strings from SZL diagnostic response.

    Returns dict of discovered fields (module name, CPU type, etc.).
    """
    result: Dict[str, str] = {}
    if not raw or len(raw) < 12:
        return result

    # Try to find printable strings >= 4 chars
    strings_found: List[str] = []
    i = 12  # skip S7 header
    while i < len(raw) - 1:
        # Try decode 2-byte length prefix + string pattern
        if i + 2 <= len(raw):
            str_len = struct.unpack_from(">H", raw, i)[0]
            if 4 <= str_len <= 64 and i + 2 + str_len <= len(raw):
                candidate = raw[i + 2: i + 2 + str_len]
                try:
                    text = candidate.decode("ascii", errors="strict")
                    if text.isprintable() and len(text.strip()) >= 3:
                        strings_found.append(text.strip())
                        i += 2 + str_len
                        continue
                except (UnicodeDecodeError, ValueError):
                    pass
        i += 1

    if strings_found:
        result["module_info"] = "; ".join(strings_found[:5])

    # CPU state: scan for 0x08 0x00 (STOP) or 0x08 0x01 (RUN)
    for i in range(len(raw) - 1):
        if raw[i] == 0x08:
            state_byte = raw[i + 1]
            if state_byte == 0x00:
                result["cpu_state"] = "STOP"
            elif state_byte == 0x01:
                result["cpu_state"] = "RUN"
            elif state_byte == 0x02:
                result["cpu_state"] = "HOLD"
            break

    return result
