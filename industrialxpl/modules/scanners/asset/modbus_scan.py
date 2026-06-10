# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus TCP Device Identification Scanner.

Probes Modbus TCP slaves using FC 17 (Report Server ID) and
FC 43/14 (Read Device Identification) to extract vendor, product code,
revision and device metadata.

Supports:
  - Custom register/coil address expressions (individual, range, Modicon notation)
  - FC override (FC1-FC4)
  - Port ranges
  - T0-T5 timing profiles
"""

import struct

from industrialxpl.core.exploit import (
    mute, print_error, print_info, print_status, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


class Exploit(ModbusBaseExploit):
    """Modbus TCP Device Identification Scanner."""

    __info__ = {
        "name": "Modbus TCP Device Identification Scanner",
        "description": (
            "Probes Modbus TCP devices using FC 17 (Report Server ID) and "
            "FC 43/14 (Read Device Identification) to extract vendor, product "
            "code, revision, and device metadata. Identifies PLC/RTU models "
            "and firmware versions. Supports custom address expressions, "
            "FC override, port ranges, and T0-T5 timing profiles."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        ),
        "devices": (
            "Any Modbus TCP device",
            "Schneider Electric Modicon",
            "Allen-Bradley MicroLogix/CompactLogix",
            "Siemens S7 (Modbus module)",
            "Wago 750 series",
            "ABB AC500",
        ),
        "impact":   "READ",
        "severity": "info",
        "mitre":    ["T0846"],
        "status":   "confirmed",
    }

    _DEFAULT_FC   = 43
    _DEFAULT_REGS = "0"

    # Unit ID range scan
    scan_range = __import__("industrialxpl.core.exploit.option", fromlist=["OptBool"]).OptBool(
        False, "Scan all Unit IDs 1-247"
    )

    def _probe_device(self, sock: ModbusTCPSocket) -> bool:
        """Run FC43/MEI and FC17 probes. Returns True if device responded."""
        found = False

        # FC43/MEI
        resp = sock.read_device_identification()
        if resp and len(resp) > 8:
            fc_resp = resp[7]
            if fc_resp == 0x2B:
                found = True
                print_success("  FC43 Device Identification:")
                obj_labels = {
                    0x00: "VendorName", 0x01: "ProductCode",
                    0x02: "Revision",   0x03: "VendorURL",
                    0x04: "ProductName", 0x05: "ModelName",
                }
                off = 9
                try:
                    obj_count = resp[off + 2]
                    off += 3
                    for _ in range(obj_count):
                        if off + 2 > len(resp):
                            break
                        oid = resp[off]
                        olen = resp[off + 1]
                        oval = resp[off + 2: off + 2 + olen].decode("ascii", errors="replace")
                        print_info("    {:20s}: {}".format(obj_labels.get(oid, "ObjID_0x{:02X}".format(oid)), oval))
                        off += 2 + olen
                except Exception:
                    pass
            elif fc_resp & 0x80:
                exc = resp[8] if len(resp) > 8 else "?"
                print_status("  FC43 exception {} — MEI not supported, device present".format(exc))
                found = True

        # FC17 Report Server ID
        resp17 = sock.report_server_id()
        if resp17 and len(resp17) > 8 and resp17[7] == 0x11:
            found = True
            payload = resp17[9:].decode("ascii", errors="replace").strip("\x00")
            if payload:
                print_success("  FC17 Server ID  : {}".format(payload))

        return found

    def run(self) -> None:
        ports   = self._get_ports()
        timing  = self._get_timing()
        addresses = self._get_addresses()
        fc      = self._resolve_fc(addresses.implied_fc)

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        self._print_timing()
        self._print_address_plan(addresses, fc)

        unit_ids = range(1, 248) if self.scan_range else [self.unit_id]

        for port in ports:
            for uid in unit_ids:
                with ModbusTCPSocket(self.target, port, uid, timing) as sock:
                    if not sock._sock:
                        if not self.scan_range:
                            print_error("  Cannot connect to {}:{}".format(self.target, port))
                        continue

                    print_status("Probing {}:{} unit_id={}".format(self.target, port, uid))
                    found = self._probe_device(sock)

                    # Additional register read with selected FC
                    if fc in (1, 2, 3, 4):
                        start, qty = addresses.as_bulk()
                        resp = sock.send_fc(fc, start, min(qty, 125))
                        if resp and len(resp) > 8 and not (resp[7] & 0x80):
                            payload = resp[9:]
                            if fc in (1, 2):
                                bits = ""
                                for byte in payload:
                                    bits += "{:08b}".format(byte)[::-1]
                                print_success("  FC{:02d} addr {:5d}-{:5d}: {}".format(
                                    fc, start, start + qty - 1, bits[:qty]
                                ))
                            elif fc in (3, 4):
                                regs = []
                                for i in range(0, len(payload) - 1, 2):
                                    regs.append(struct.unpack(">H", payload[i: i + 2])[0])
                                print_success("  FC{:02d} addr {:5d}-{:5d}: {}".format(
                                    fc, start, start + qty - 1,
                                    ["{} (0x{:04X})".format(v, v) for v in regs]
                                ))

                    if not found and not self.scan_range:
                        print_error("  No Modbus response from {}:{}".format(self.target, port))

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
