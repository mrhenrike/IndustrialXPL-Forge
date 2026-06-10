# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus TCP service detection scanner.

Sends a minimal Modbus FC04 (Read Input Registers) request and checks
the response header to confirm Modbus/TCP is listening.

Supports port ranges and T0-T5 timing profiles.
"""

import struct

from industrialxpl.core.exploit import (
    mute, print_error, print_info, print_status, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


_TX_ID = 0x21


class Exploit(ModbusBaseExploit):
    __info__ = {
        "name":             "Modbus TCP Service Detection",
        "description":      (
            "Detects Modbus/TCP services by sending a minimal FC04 request and validating "
            "the Transaction ID echo. Supports port ranges and T0-T5 timing profiles."
        ),
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       ("https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",),
        "devices":          ("PLC", "RTU", "Gateway", "Any Modbus/TCP device"),
        "impact":           "READ",
        "exploit_type":     "Service Detection",
        "source_poc":       "Python native (raw socket)",
        "mitre_techniques": ["T0846", "T0842"],
        "mitre_tactics":    ["Discovery"],
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
    }

    _DEFAULT_FC   = 4
    _DEFAULT_REGS = "1"

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
        self._print_timing()
        print_info("")

        for port in ports:
            with ModbusTCPSocket(self.target, port, self.unit_id, timing) as sock:
                if not sock._sock:
                    print_info("{}:{} — closed / no response".format(self.target, port))
                    continue
                # FC04 probe
                pdu  = struct.pack(">BHH", 0x04, 0x0001, 0x0001)
                resp = sock.send_pdu(pdu)
                if resp and len(resp) >= 4:
                    print_success("{}:{} — Modbus/TCP DETECTED (unit_id={})".format(
                        self.target, port, self.unit_id
                    ))
                else:
                    print_info("{}:{} — no Modbus response".format(self.target, port))
