# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus TCP service detection scanner.

Sends a configurable Modbus read request (FC1-FC4) and checks the response
to confirm Modbus/TCP is listening. Respects REGISTERS/COILS and FC options.

Supports port ranges and T0-T5 timing profiles.
"""

from industrialxpl.core.exploit import (
    mute, print_error, print_info, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


class Exploit(ModbusBaseExploit):
    __info__ = {
        "name":             "Modbus TCP Service Detection",
        "description":      (
            "Detects Modbus/TCP services by sending a read request (FC1-FC4) and "
            "validating the response. Supports custom register/coil ranges, FC override, "
            "port ranges, and T0-T5 timing profiles."
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

        ports     = self._get_ports()
        timing    = self._get_timing()
        addresses = self._get_addresses()
        fc        = self._resolve_fc(addresses.implied_fc)
        start, qty = addresses.as_bulk()

        sim = getattr(self, "_simulate_mode", self.simulate)

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info("  Unit ID : {}".format(self.unit_id))
        self._print_timing()
        self._print_address_plan(addresses, fc)
        print_info("")

        if sim:
            for port in ports:
                sock = modbus_connect(self.target, port, timing.socket_timeout)
                if sock:
                    sock.close()
                    print_success("[SIMULATE] {}:{} — port open, would probe FC{:02d} addr {} qty {}".format(
                        self.target, port, fc, start, min(qty, 125)
                    ))
                else:
                    print_info("[SIMULATE] {}:{} — closed / no response".format(self.target, port))
            return

        for port in ports:
            with ModbusTCPSocket(self.target, port, self.unit_id, timing) as sock:
                if not sock._sock:
                    print_info("{}:{} — closed / no response".format(self.target, port))
                    continue
                resp = sock.send_fc(fc, start, min(qty, 125))
                if resp and len(resp) >= 4:
                    print_success("{}:{} — Modbus/TCP DETECTED (unit_id={}, FC{:02d})".format(
                        self.target, port, self.unit_id, fc
                    ))
                else:
                    print_info("{}:{} — no Modbus response".format(self.target, port))
