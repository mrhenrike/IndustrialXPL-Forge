# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus FC43/MEI Banner Grabbing — vendor and product identification.

Sends FC 43 (Read Device Identification) to extract vendor name,
product code, firmware version, and serial number.

Supports port ranges and T0-T5 timing profiles.
"""

import struct
from typing import Dict

from industrialxpl.core.exploit import (
    mute, print_error, print_info, print_status, print_success, print_table,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect

_OBJ_LABELS: Dict[int, str] = {
    0x00: "VendorName",
    0x01: "ProductCode",
    0x02: "MajorMinorRevision",
    0x03: "VendorURL",
    0x04: "ProductName",
    0x05: "ModelName",
    0x06: "UserApplicationName",
}


def _parse_mei(data: bytes) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if len(data) < 11:
        return result
    off = 9
    try:
        obj_count = data[off + 2]
        off += 3
        for _ in range(obj_count):
            if off + 2 > len(data):
                break
            oid  = data[off]
            olen = data[off + 1]
            oval = data[off + 2: off + 2 + olen].decode("ascii", errors="replace")
            result[_OBJ_LABELS.get(oid, "Obj_0x{:02X}".format(oid))] = oval
            off += 2 + olen
    except Exception:
        pass
    return result


class Exploit(ModbusBaseExploit):
    __info__ = {
        "name":         "Modbus FC43 Device Identification Banner Grabbing",
        "description":  (
            "Uses Modbus FC43/MEI (Read Device Identification) to extract vendor, "
            "product name, firmware version, and serial number from PLCs/RTUs/gateways. "
            "Supports port ranges and T0-T5 timing profiles."
        ),
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   ("https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",),
        "devices":      ("Any Modbus/TCP device supporting FC43"),
        "impact":       "INFO",
        "exploit_type": "Information Disclosure",
        "source_poc":   "Python native",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "INFO",
        "mitre_techniques": ["T0888", "T0802", "T0861"],
        "mitre_tactics":    ["Discovery"],
    }

    _DEFAULT_FC   = 43
    _DEFAULT_REGS = "0"

    @mute
    def check(self) -> bool:
        ports  = self._get_ports()
        timing = self._get_timing()
        for port in ports:
            sock = modbus_connect(self.target, port, timing.socket_timeout)
            if sock:
                sock.close()
                return True
        return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        ports  = self._get_ports()
        timing = self._get_timing()

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info("  Unit ID : {}".format(self.unit_id))
        self._print_timing()
        print_info("")

        for port in ports:
            with ModbusTCPSocket(self.target, port, self.unit_id, timing) as sock:
                if not sock._sock:
                    print_info("{}:{} — cannot connect".format(self.target, port))
                    continue

                print_status("Grabbing FC43/MEI banner from {}:{}...".format(self.target, port))
                resp = sock.read_device_identification()
                if not resp or len(resp) < 8:
                    print_error("  No response from {}:{}".format(self.target, port))
                    continue

                fc_resp = resp[7]
                if fc_resp & 0x80:
                    exc = resp[8] if len(resp) > 8 else "?"
                    print_info("  FC43 exception {} — device present but MEI unsupported".format(exc))
                    continue

                info = _parse_mei(resp)
                if info:
                    rows = [(k, v) for k, v in info.items()]
                    print_table(
                        ["Field", "Value"],
                        rows,
                        title="FC43 Banner — {}:{}".format(self.target, port),
                    )
                else:
                    print_info("  FC43 responded but no identifiable objects in payload")
