# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus/TCP ICS Scanner.

Fingerprints PLCs, RTUs and HMIs via Modbus function codes.
Supports custom register/coil address expressions, FC selection,
port ranges and T0-T5 timing profiles.

References:
  - Modbus Application Protocol Specification V1.1b3
  - ICS-CERT Advisory on exposed Modbus services
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)
"""

import struct
from typing import Optional

from industrialxpl.core.exploit import (
    mute, print_error, print_info, print_status, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


def _parse_mei_response(data: bytes) -> dict:
    """Parse FC43/MEI Type 14 response into a dict of object values."""
    result = {}
    if len(data) < 8:
        return result
    offset = 9
    obj_labels = {
        0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
        0x03: "VendorURL",  0x04: "ProductName", 0x05: "ModelName",
    }
    try:
        _conformity = data[offset]
        _more       = data[offset + 1]
        obj_count   = data[offset + 2]
        offset += 3
        for _ in range(obj_count):
            if offset + 2 > len(data):
                break
            obj_id  = data[offset]
            obj_len = data[offset + 1]
            obj_val = data[offset + 2: offset + 2 + obj_len].decode("ascii", errors="replace")
            label   = obj_labels.get(obj_id, "Object_0x{:02X}".format(obj_id))
            result[label] = obj_val
            offset += 2 + obj_len
    except Exception:
        pass
    return result


class Exploit(ModbusBaseExploit):
    """Modbus/TCP ICS Scanner — device identification and register enumeration."""

    __info__ = {
        "name":        "Modbus/TCP ICS Scanner",
        "description": (
            "Fingerprints Modbus/TCP devices using FC43/MEI (vendor, product, firmware), "
            "FC1 (coils), and FC3 (holding registers). Supports custom address expressions "
            "(individual, ranges, Schneider/Modicon 5-digit notation), FC override, "
            "port ranges, and T0-T5 timing profiles."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "PLC", "RTU", "HMI", "Modbus gateway",
            "Schneider Modicon", "Siemens", "Rockwell Allen-Bradley", "ABB",
        ),
        "impact":   "READ",
        "severity": "info",
        "mitre":    ["T0846"],
    }

    _DEFAULT_FC   = 3         # FC3 Holding Registers
    _DEFAULT_REGS = "0-9"     # First 10 holding registers by default

    def run(self) -> None:  # noqa: C901
        ports   = self._get_ports()
        timing  = self._get_timing()
        addresses = self._get_addresses()
        fc      = self._resolve_fc(addresses.implied_fc)

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info("  Unit ID : {}".format(self.unit_id))
        self._print_timing()
        self._print_address_plan(addresses, fc)
        print_info("")

        for port in ports:
            print_status("Probing {}:{} ...".format(self.target, port))
            with ModbusTCPSocket(self.target, port, self.unit_id, timing) as sock:
                if not sock._sock:
                    print_error("  Cannot connect to {}:{}".format(self.target, port))
                    continue

                # FC43/MEI — Device Identification
                mei_resp = sock.read_device_identification()
                if mei_resp and len(mei_resp) > 8 and mei_resp[7] == 0x2B:
                    info = _parse_mei_response(mei_resp)
                    print_success("  Device identified (FC43/MEI):")
                    for k, v in info.items():
                        print_info("    {:25s}: {}".format(k, v))
                elif mei_resp and len(mei_resp) > 7 and mei_resp[7] & 0x80:
                    exc = mei_resp[8] if len(mei_resp) > 8 else "?"
                    print_status("  FC43 exception {} — device present but MEI unsupported".format(exc))
                else:
                    print_status("  FC43 no response — trying basic FC probe")

                # FC17 — Report Server ID (firmware/device string)
                sid_resp = sock.report_server_id()
                if sid_resp and len(sid_resp) > 8 and sid_resp[7] == 0x11:
                    payload = sid_resp[9:]
                    decoded = payload.decode("ascii", errors="replace").strip("\x00")
                    if decoded:
                        print_success("  FC17 Server ID: {}".format(decoded))

                # Requested FC on selected addresses
                start, qty = addresses.as_bulk()
                resp = sock.send_fc(fc, start, min(qty, 125))
                self._print_fc_result(resp, fc, addresses, start)

    def _print_fc_result(self, resp, fc, addresses, start):
        if not resp or len(resp) < 9:
            print_info("  FC{:02d}: no response or too short".format(fc))
            return

        resp_fc = resp[7]
        if resp_fc & 0x80:
            exc = resp[8] if len(resp) > 8 else "?"
            print_info("  FC{:02d}: exception code {} (device denied request)".format(fc, exc))
            return

        payload = resp[9:]
        if fc in (1, 2):
            # Bit-level response
            bits = ""
            for byte in payload:
                bits += "{:08b}".format(byte)[::-1]
            offsets = [a.offset for a in addresses]
            wanted  = {a.offset: bits[a.offset - start] if a.offset - start < len(bits) else "?" for a in addresses}
            print_success("  FC{:02d} ({}) — {} coil/bit values:".format(
                fc, "Coils" if fc == 1 else "Discrete Inputs", len(offsets)
            ))
            for off, bit in wanted.items():
                print_info("    addr {:5d}: {}".format(off, "ON" if bit == "1" else "OFF"))
        elif fc in (3, 4):
            # Word-level response
            regs = []
            for i in range(0, len(payload) - 1, 2):
                regs.append(struct.unpack(">H", payload[i: i + 2])[0])
            label = "Holding" if fc == 3 else "Input"
            print_success("  FC{:02d} ({} Registers) — {} values:".format(fc, label, len(regs)))
            for idx, addr_obj in enumerate(addresses):
                reg_idx = addr_obj.offset - start
                val = regs[reg_idx] if reg_idx < len(regs) else None
                if val is not None:
                    print_info("    addr {:5d}: {:6d}  (0x{:04X})".format(
                        addr_obj.offset, val, val
                    ))

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
