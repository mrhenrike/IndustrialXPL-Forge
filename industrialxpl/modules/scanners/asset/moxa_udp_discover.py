"""Moxa Industrial Device Discovery via ADDP (Advanced Device Discovery Protocol).

Sends a UDP broadcast on port 4800 using the Moxa ADDP protocol to discover
Moxa industrial devices (serial device servers, gateways, industrial routers)
on the local network.

Ported from: Metasploit auxiliary/scanner/scada/moxa_discover.rb
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
        "name":         "Moxa ADDP Device Discovery (UDP Broadcast)",
        "description":  "Sends a Moxa ADDP (Advanced Device Discovery Protocol) "
                        "UDP probe to discover Moxa industrial serial device servers, "
                        "gateways, and industrial routers on the network. "
                        "Devices responding reveal model, MAC, firmware, and IP.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://www.moxa.com/",
        ),
        "devices":      ("Moxa NPort", "Moxa MiiNePort", "Moxa industrial routers",
                         "Moxa serial device servers"),
        "impact":       "INFO",
        "exploit_type": "Device Discovery",
        "source_poc":   "Metasploit auxiliary/scanner/scada/moxa_discover.rb (ported to Python)",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "INFO",
        "mitre_techniques": ["T0846.002", "T0888"],
        "mitre_tactics":    ["Discovery"],
    }

    target  = OptIP("255.255.255.255", "Target IP (255.255.255.255 for broadcast)")
    port    = OptPort(4800, "Moxa ADDP UDP port (default 4800)")
    timeout = OptInteger(3, "Listen timeout (seconds)")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    # Moxa ADDP identify probe: function code 0x01
    _PROBE = b"\x01\x00\x00\x08\x00\x00\x00\x00"

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        if self.simulate:
            DestructiveGate.print_simulation(
                description="Would send Moxa ADDP probe (8 bytes) to {}:{}/UDP "
                            "and collect responses from Moxa devices.".format(
                                self.target, self.port),
                payload_hex="01 00 00 08 00 00 00 00",
                payload_human="Moxa ADDP Identify (function 0x01) broadcast",
                mitre_techniques=["T0846.002"],
            )
            return

        print_status("Broadcasting Moxa ADDP probe to {}:{}…".format(self.target, self.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self.timeout)

        devices = []
        try:
            sock.sendto(self._PROBE, (self.target, self.port))
            while True:
                try:
                    resp, addr = sock.recvfrom(256)
                    # Valid response: starts with 0x81 (0x01 | 0x80), length 24 bytes
                    # Moxa OUI: 00:90:e8 at bytes 14-16
                    if (len(resp) == 24 and resp[0] == 0x81 and
                            resp[14:17] == b"\x00\x90\xe8"):
                        ip = ".".join(str(b) for b in resp[4:8])
                        mac = ":".join("{:02x}".format(b) for b in resp[14:20])
                        devices.append((addr[0], ip, mac))
                except socket.timeout:
                    break
        finally:
            sock.close()

        if devices:
            print_table(
                ["Response IP", "Device IP", "MAC Address"],
                devices,
                title="Moxa Devices Found",
            )
            for addr, ip, mac in devices:
                print_success("Moxa device at {}: ip={}, mac={}".format(addr, ip, mac))
        else:
            print_info("No Moxa devices responded.")
