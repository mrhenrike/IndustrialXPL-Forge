"""Modbus TCP service detection scanner.

Sends a minimal Modbus FC04 (Read Input Registers) request and checks
the response header to confirm Modbus/TCP is listening.
Python-pure implementation using raw sockets.

Ported from: Metasploit auxiliary/scanner/scada/modbusdetect.rb
Protocol reference: Modbus Application Protocol Specification v1.1b3
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
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Modbus TCP Service Detection",
        "description":      "Detects a Modbus/TCP service by sending a minimal FC04 "
                            "(Read Input Registers) request and validating the response "
                            "Transaction ID echo. Works on any Modbus/TCP device.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        ),
        "devices":          ("PLC", "RTU", "Gateway", "Any Modbus/TCP device"),
        "impact":           "READ",
        "exploit_type":     "Service Detection",
        "source_poc":       "Python native (raw socket)",
        "mitre_techniques": ["T0846", "T0846.001", "T0842"],
        "mitre_tactics":    ["Discovery"],
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
    }

    target  = OptIP("", "Target Modbus/TCP host")
    port    = OptPort(502, "Modbus TCP port (default 502)")
    unit_id = OptInteger(1, "Modbus unit identifier (1-255)", min_value=1, max_value=255)
    timeout = OptInteger(5, "Socket timeout in seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    @mute
    def check(self) -> bool:
        """Return True if Modbus/TCP is responding on the target."""
        if not self.target:
            return False
        try:
            # Modbus MBAP header: TransID=0x2100, ProtocolID=0x0000, Length=6, UnitID
            # FC=04 Read Input Registers, Addr=0x0001, Count=0x0000
            tx_id = 0x21
            pdu = struct.pack(">HHHBBHH", tx_id, 0, 6, self.unit_id, 0x04, 0x0001, 0x0000)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(pdu)
            data = sock.recv(256)
            sock.close()
            if len(data) >= 4 and data[0:2] == struct.pack(">H", tx_id):
                return True
        except Exception:
            pass
        return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description="Would send Modbus FC04 request to {}:{} unit_id={} "
                            "and check if response echoes Transaction ID 0x2100.".format(
                                self.target, self.port, self.unit_id
                            ),
                payload_hex="21 00 00 00 00 06 {:02X} 04 00 01 00 00".format(self.unit_id),
                payload_human="Modbus MBAP + FC04 Read Input Registers (non-destructive probe)",
                mitre_techniques=["T0846.001", "T0842"],
            )
            return

        print_status("Probing {}:{} (unit_id={})…".format(self.target, self.port, self.unit_id))
        if self.check():
            print_success("{}:{} — Modbus/TCP DETECTED (unit_id={})".format(
                self.target, self.port, self.unit_id
            ))
        else:
            print_info("{}:{} — No Modbus response.".format(self.target, self.port))
