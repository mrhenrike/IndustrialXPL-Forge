# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus/TCP ICS Scanner — device identification and register/coil enumeration.

Modes:
  simulate=true  (default, SAFEMODE always blocks otherwise)
    - Lightweight TCP check + SIMULATED realistic output.
    - FC43/FC17 probe only. Returns synthetic register/coil values.
    - Zero real reads. Output labeled [SIMULATE].

  simulate=false + destructive=false  (requires setg SAFEMODE false)
    - Real FC43/FC17/FC1/FC2/FC3/FC4 reads.
    - Returns ACTUAL device data.
    - Write operations (FC5/FC6/FC15/FC16) BLOCKED.

  simulate=false + destructive=true  (requires setg SAFEMODE false)
    - Full read + write operations.
    - FC5 (write coil), FC6 (write register), FC15/FC16 (batch).
    - Requires explicit confirmation. May alter device state irreversibly.
    - Set WRITE_VALUE to specify value for write operations.

References:
  - Modbus Application Protocol Specification V1.1b3
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)
"""

import random
import socket as _socket
import struct
from typing import Optional

from industrialxpl.core.exploit import (
    OptString, mute, print_error, print_info, print_status, print_success, print_warning,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


def _parse_mei_response(data: bytes) -> dict:
    """Parse FC43/MEI Type 14 response."""
    result = {}
    if len(data) < 8:
        return result
    offset = 9
    obj_labels = {
        0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
        0x03: "VendorURL",  0x04: "ProductName", 0x05: "ModelName",
    }
    try:
        obj_count = data[offset + 2]
        offset += 3
        for _ in range(obj_count):
            if offset + 2 > len(data):
                break
            oid  = data[offset]
            olen = data[offset + 1]
            oval = data[offset + 2: offset + 2 + olen].decode("ascii", errors="replace")
            result[obj_labels.get(oid, "Obj_0x{:02X}".format(oid))] = oval
            offset += 2 + olen
    except Exception:
        pass
    return result


class Exploit(ModbusBaseExploit):
    """Modbus/TCP ICS Scanner -- device identification and register/coil enumeration."""

    __info__ = {
        "name":        "Modbus/TCP ICS Scanner",
        "description": (
            "Fingerprints Modbus/TCP devices using FC43/MEI, FC17, FC1/FC2 (coils), "
            "and FC3/FC4 (holding registers). Supports simulate (safe), read (real reads), "
            "and destructive (read+write) modes. "
            "See 'help safemode' for the full mode explanation."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
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

    _DEFAULT_FC   = 3
    _DEFAULT_REGS = "0-9"

    # Extra option for destructive write operations
    write_value = OptString("", "Value to write when destructive=true (integer for registers, 0/1 for coils)")

    def run(self) -> None:  # noqa: C901
        ports     = self._get_ports()
        timing    = self._get_timing()
        addresses = self._get_addresses()
        fc        = self._resolve_fc(addresses.implied_fc)

        # Resolve execution mode flags set by command_run
        sim   = getattr(self, "_simulate_mode", self.simulate)
        destr = getattr(self, "_destructive_mode", self.destructive)

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info("  Unit ID : {}".format(self.unit_id))
        print_info("  Mode    : {}".format(
            "[SIMULATE] check + synthetic output" if sim else
            ("[READ+WRITE / DESTRUCTIVE]" if destr else "[READ] real reads, writes blocked")
        ))
        self._print_timing()
        self._print_address_plan(addresses, fc)
        print_info("")

        # ── MODE 1: SIMULATE ─────────────────────────────────────────────────
        if sim:
            for port in ports:
                try:
                    s = _socket.create_connection((self.target, port), timeout=timing.socket_timeout)
                    s.close()
                    print_success("  [SIMULATE] {}:{} OPEN -- Modbus/TCP device present".format(
                        self.target, port
                    ))
                    print_info("")
                    print_info("  [SIMULATE] If VULNERABLE, real reads would return:")
                    print_info("    FC43 VendorName   : [Simulated] Schneider Electric")
                    print_info("    FC43 ProductCode  : [Simulated] Modicon M340")
                    print_info("    FC43 Revision     : [Simulated] 2.60")
                    print_info("    FC17 Server ID    : [Simulated] SN=1A2B3C4D FW=V2.60")
                    start, qty = addresses.as_bulk()
                    if fc in (3, 4):
                        label = "Holding" if fc == 3 else "Input"
                        regs = [random.randint(0, 65535) for _ in range(min(qty, 10))]
                        print_info("    FC{:02d} {} Registers (addr {}-{}):".format(
                            fc, label, start, start + len(regs) - 1
                        ))
                        for i, v in enumerate(regs):
                            print_info("      addr {:5d}: {:6d}  (0x{:04X})  [SIMULATED]".format(
                                start + i, v, v
                            ))
                    elif fc in (1, 2):
                        label = "Coils" if fc == 1 else "Discrete Inputs"
                        bits = "".join(str(random.randint(0, 1)) for _ in range(min(qty, 16)))
                        print_info("    FC{:02d} {} (addr {}-{}): {}  [SIMULATED]".format(
                            fc, label, start, start + qty - 1, bits
                        ))
                    print_info("")
                    print_warning("  To read REAL values: setg SAFEMODE false && set SIMULATE false && run")
                except Exception:
                    print_info("  [SIMULATE] {}:{} no response (closed or filtered)".format(
                        self.target, port
                    ))
            return

        # ── MODE 2: READ (real reads) and MODE 3: DESTRUCTIVE (read+write) ──
        for port in ports:
            print_status("Connecting {}:{} ...".format(self.target, port))
            with ModbusTCPSocket(self.target, port, self.unit_id, timing) as sock:
                if not sock._sock:
                    print_error("  Cannot connect to {}:{}".format(self.target, port))
                    continue

                # FC43/MEI Device Identification (always)
                mei_resp = sock.read_device_identification()
                if mei_resp and len(mei_resp) > 8 and mei_resp[7] == 0x2B:
                    info = _parse_mei_response(mei_resp)
                    print_success("  FC43 Device Identification:")
                    for k, v in info.items():
                        print_info("    {:25s}: {}".format(k, v))
                elif mei_resp and len(mei_resp) > 7 and mei_resp[7] & 0x80:
                    exc = mei_resp[8] if len(mei_resp) > 8 else "?"
                    print_status("  FC43 exception {} -- device present, MEI not supported".format(exc))
                else:
                    print_status("  FC43 no response")

                # FC17 Server ID (always)
                sid_resp = sock.report_server_id()
                if sid_resp and len(sid_resp) > 8 and sid_resp[7] == 0x11:
                    decoded = sid_resp[9:].decode("ascii", errors="replace").strip("\x00")
                    if decoded:
                        print_success("  FC17 Server ID: {}".format(decoded))

                # FC reads for selected addresses
                start, qty = addresses.as_bulk()
                resp = sock.send_fc(fc, start, min(qty, 125))
                self._print_fc_result(resp, fc, addresses, start)

                # DESTRUCTIVE: write operations (FC5/FC6)
                if destr:
                    print_info("")
                    print_warning("  [DESTRUCTIVE] Write operations:")
                    wv_str = str(self.write_value).strip()
                    coils_set = str(self.coils).strip()

                    if not wv_str:
                        print_info("    Set WRITE_VALUE to enable writes.")
                        print_info("    Example: set WRITE_VALUE 0  -- zero all selected registers/coils")
                        print_info("    Example: set WRITE_VALUE 1  -- set coils ON")
                    else:
                        wv = int(wv_str) & 0xFFFF
                        for addr_obj in addresses:
                            if coils_set or fc in (1, 2):
                                # FC5: Write Single Coil
                                val_bool = bool(wv)
                                r = sock.write_single_coil(addr_obj.offset, val_bool)
                                code = r[7] if r and len(r) > 7 else -1
                                if code == 0x05:
                                    print_success("    FC05 Write coil addr {:5d} -> {}".format(
                                        addr_obj.offset, "ON" if val_bool else "OFF"
                                    ))
                                else:
                                    print_warning("    FC05 Write coil addr {:5d} -> REJECTED (code=0x{:02X})".format(
                                        addr_obj.offset, code & 0xFF
                                    ))
                            else:
                                # FC6: Write Single Register
                                r = sock.write_single_register(addr_obj.offset, wv)
                                code = r[7] if r and len(r) > 7 else -1
                                if code == 0x06:
                                    print_success("    FC06 Write reg  addr {:5d} -> {} (0x{:04X})".format(
                                        addr_obj.offset, wv, wv
                                    ))
                                else:
                                    print_warning("    FC06 Write reg  addr {:5d} -> REJECTED (code=0x{:02X})".format(
                                        addr_obj.offset, code & 0xFF
                                    ))

    def _print_fc_result(self, resp, fc, addresses, start):
        if not resp or len(resp) < 9:
            print_info("  FC{:02d}: no response".format(fc))
            return
        resp_fc = resp[7]
        if resp_fc & 0x80:
            exc = resp[8] if len(resp) > 8 else "?"
            print_info("  FC{:02d}: exception {} (device denied)".format(fc, exc))
            return
        payload = resp[9:]
        if fc in (1, 2):
            bits = ""
            for byte in payload:
                bits += "{:08b}".format(byte)[::-1]
            print_success("  FC{:02d} ({}) -- {} values:".format(
                fc, "Coils" if fc == 1 else "Discrete Inputs", len(addresses)
            ))
            for a in addresses:
                idx = a.offset - start
                bit = bits[idx] if idx < len(bits) else "?"
                print_info("    addr {:5d}: {}".format(a.offset, "ON" if bit == "1" else "OFF"))
        elif fc in (3, 4):
            regs = []
            for i in range(0, len(payload) - 1, 2):
                regs.append(struct.unpack(">H", payload[i: i + 2])[0])
            label = "Holding" if fc == 3 else "Input"
            print_success("  FC{:02d} ({} Registers) -- {} values:".format(fc, label, len(regs)))
            for a in addresses:
                idx = a.offset - start
                if idx < len(regs):
                    v = regs[idx]
                    print_info("    addr {:5d}: {:6d}  (0x{:04X})".format(a.offset, v, v))

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
