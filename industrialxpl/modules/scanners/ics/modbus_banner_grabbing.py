"""Modbus FC43 / MEI Banner Grabbing — Vendor and Product Identification.

Sends a Modbus Function Code 43 (Read Device Identification) request to
extract vendor name, product code, firmware version, and serial number
from Modbus-capable devices.

Ported from: Metasploit auxiliary/scanner/scada/modbus_banner_grabbing.rb
"""

import socket
import struct

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":         "Modbus FC43 Device Identification Banner Grabbing",
        "description":  "Uses Modbus Function Code 43 (Read Device Identification / MEI) "
                        "to extract vendor name, product name, firmware version, and "
                        "serial number from Modbus-capable PLCs, RTUs, and gateways.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        ),
        "devices":      ("Any Modbus/TCP device supporting FC43"),
        "impact":       "INFO",
        "exploit_type": "Information Disclosure",
        "source_poc":   "Metasploit auxiliary/scanner/scada/modbus_banner_grabbing.rb (ported)",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "INFO",
        "mitre_techniques": ["T0888", "T0802", "T0861"],
        "mitre_tactics":    ["Discovery"],
    }

    target  = OptIP("", "Target Modbus/TCP host")
    port    = OptPort(502, "Modbus TCP port")
    unit_id = OptInteger(1, "Modbus unit ID (1-255)", min_value=1, max_value=255)
    timeout = OptInteger(5, "Socket timeout")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    _OBJECT_NAMES = {
        0x00: "Vendor Name",
        0x01: "Product Code",
        0x02: "Major Minor Revision",
        0x03: "Vendor URL",
        0x04: "Product Name",
        0x05: "Model Name",
        0x06: "Application Name",
    }

    @mute
    def check(self) -> bool:
        return bool(self._query_mei())

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description="Would send Modbus FC43/MEI (Read Device Identification) "
                            "to {}:{} unit_id={} and parse vendor/product info.".format(
                                self.target, self.port, self.unit_id),
                payload_hex="00 01 00 00 00 05 {:02X} 2B 0E 01 00".format(self.unit_id),
                payload_human="Modbus FC43 MEI ReadDeviceIdentification (code 0x01, stream)",
                mitre_techniques=["T0888"],
            )
            return

        print_status("FC43 banner grab on {}:{} unit_id={}…".format(
            self.target, self.port, self.unit_id))
        info = self._query_mei()
        if not info:
            print_error("No FC43 response — device may not support MEI or unit_id is wrong.")
            return

        rows = [(k, v) for k, v in info.items()]
        print_table(["Object", "Value"], rows,
                    title="Modbus Device Info — {}:{}".format(self.target, self.port))

    def _query_mei(self) -> dict:
        """Send Modbus FC43 MEI (0x0E) request and parse object list."""
        results = {}
        try:
            tx_id = 0x0001
            # FC43, MEI type 0x0E, ReadDeviceId code 0x01 (streaming), object 0x00
            pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
            mbap = struct.pack(">HHH", tx_id, 0, len(pdu) + 1) + bytes([self.unit_id])
            packet = mbap + pdu

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(packet)
            resp = sock.recv(512)
            sock.close()

            if len(resp) < 9:
                return results

            # Parse objects starting at byte 9
            idx = 9
            num_objects = resp[8] if len(resp) > 8 else 0
            for _ in range(num_objects):
                if idx + 2 > len(resp):
                    break
                obj_id = resp[idx]
                obj_len = resp[idx + 1]
                obj_val = resp[idx + 2: idx + 2 + obj_len]
                name = self._OBJECT_NAMES.get(obj_id, "Object 0x{:02X}".format(obj_id))
                results[name] = obj_val.decode("ascii", errors="replace")
                idx += 2 + obj_len
        except Exception:
            pass
        return results
