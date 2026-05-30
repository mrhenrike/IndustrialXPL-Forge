# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Siemens S7-1200/1500 Hardcoded Cryptographic Key (CVE-2021-22681, OT:ICEFALL).

CVE-2021-22681 (CVSS 7.5) — Siemens S7-1200 and S7-1500 PLCs use a hardcoded
global private key in their TLS/S7comm+ communication. This hardcoded key was
extracted and published as part of the OT:ICEFALL research disclosure.

The vulnerability allows an attacker with network access to:
  1. Perform a Man-in-the-Middle (MitM) attack on TIA Portal engineering sessions
  2. Decrypt encrypted S7comm+ traffic (retrospective or live)
  3. Potentially forge authentication tokens

The hardcoded key is the same across ALL affected S7-1200/1500 devices regardless
of firmware version, making it impossible to remediate without a hardware revision.

Siemens documented this as a known design limitation in TIA Portal V16 and below.

References:
  - CVE-2021-22681 (NVD)
  - Siemens ProductCERT Advisory SSA-568428
  - Forescout Vedere Labs: OT:ICEFALL (June 2022)
  - MITRE ATT&CK ICS: T1694.002 (Hardcoded Credentials), T0889 (Modify Program)

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

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

_S7_PORT = 102

# TPKT + COTP Connection Request for S7-1200/1500
_COTP_CONNECT = bytes.fromhex(
    "03000023"          # TPKT: version 3, length 35
    "1ee0000000010000"  # COTP: CR PDU
    "c0010a"            # TPDU size option: 1024 bytes
    "c1020600"          # srctsap = 0x0600 (engineering workstation)
    "c202010200"        # dsttsap = 0x0102 (S7-1200 default)
)

# S7comm+ startup/negotiation probe
_S7PLUS_NEGOTIATE = bytes.fromhex(
    "030000191102f080"  # TPKT + COTP DT
    "72010000"          # S7comm+ magic + type
    "ca000000"          # sequence
)


def _tcp_probe(target: str, port: int, timeout: int) -> Optional[bytes]:
    """Connect to S7 port, send COTP connect, return response bytes."""
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.sendall(_COTP_CONNECT)
        resp = sock.recv(256)
        sock.close()
        return resp
    except Exception:
        return None


def _is_s7plus(resp: bytes) -> bool:
    """Return True if response indicates S7-1200/1500 (CC PDU type 0xD0)."""
    if len(resp) < 7:
        return False
    return resp[5] == 0xD0  # COTP Connect Confirm


class Exploit(Exploit):
    """Siemens S7-1200/1500 Hardcoded Cryptographic Key (CVE-2021-22681).

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Siemens S7-1200/1500 Hardcoded Crypto Key (CVE-2021-22681)",
        "description": (
            "Confirms Siemens S7-1200/1500 exposure to CVE-2021-22681 (CVSS 7.5), "
            "a hardcoded global private key used in S7comm+ TLS communications "
            "(part of OT:ICEFALL). The hardcoded key allows MitM of TIA Portal "
            "engineering sessions and decryption of S7comm+ traffic. The same key "
            "is shared across ALL affected devices and cannot be remediated without "
            "hardware revision. check() confirms S7comm+ presence on TCP/102."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22681",
            "https://cert-portal.siemens.com/productcert/html/ssa-568428.html",
            "https://www.forescout.com/research-labs/ot-icefall/",
            "https://attack.mitre.org/techniques/T1694/002/",
        ),
        "devices": (
            "Siemens SIMATIC S7-1200 (all CPU models, TIA Portal V16 and below)",
            "Siemens SIMATIC S7-1500 (all CPU models, TIA Portal V16 and below)",
        ),
        "impact": "HIGH",
        "cve": "CVE-2021-22681",
        "cvss": "7.5",
        "severity": "HIGH",
        "mitre_techniques": ["T1694.002", "T0889"],
        "mitre_tactics": ["Initial Access", "Impair Process Control"],
    }

    target = OptIP("", "Target S7-1200/1500 PLC IP")
    port = OptPort(_S7_PORT, "ISO-on-TCP port (default 102)")
    timeout = OptInteger(5, "Socket timeout in seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    @mute
    def check(self) -> bool:
        """Return True if S7comm+ COTP confirm is received on TCP/102."""
        if not self.target:
            return False
        resp = _tcp_probe(self.target, self.port, 3)
        return resp is not None and _is_s7plus(resp)

    def run(self) -> None:
        """Confirm S7comm+ presence and describe the hardcoded key vulnerability."""
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Would connect to {}:{}/TCP and send COTP Connect Request to "
                    "identify an S7-1200/1500 PLC. CVE-2021-22681 (CVSS 7.5, OT:ICEFALL) — "
                    "these PLCs use a single hardcoded global private key across all units "
                    "for S7comm+ TLS. Key extracted by Forescout Vedere Labs. "
                    "Attack scenario: MitM TIA Portal engineering sessions to intercept "
                    "ladder logic, credentials, and commands. Cannot be patched without "
                    "hardware revision. Network isolation is the primary mitigation.".format(
                        self.target, self.port
                    )
                ),
                payload_hex=" ".join("{:02X}".format(b) for b in _COTP_CONNECT),
                payload_human=(
                    "COTP Connect Request: srcTSAP=0x0600 (WS) -> dstTSAP=0x0102 "
                    "(S7-1200) -> S7comm+ session -> hardcoded TLS key in use"
                ),
                mitre_techniques=["T1694.002", "T0889"],
            )
            return

        print_status("[CVE-2021-22681] Probing S7comm+ on {}:{}...".format(
            self.target, self.port
        ))
        resp = _tcp_probe(self.target, self.port, self.timeout)
        if resp is None:
            print_error("[CVE-2021-22681] No response on TCP/{}.".format(self.port))
            return

        if _is_s7plus(resp):
            print_success(
                "[CVE-2021-22681] S7comm+ COTP Connect Confirm received from {}:{}!".format(
                    self.target, self.port
                )
            )
            print_warning(
                "[CVE-2021-22681] If this is a Siemens S7-1200/1500 running TIA Portal "
                "V16 or earlier, it is affected by the hardcoded global crypto key "
                "(CVE-2021-22681). MitM attacks on engineering sessions are feasible. "
                "Mitigation: Upgrade to TIA Portal V17+, enable network isolation, "
                "and restrict access to TCP/102."
            )
            print_info("[CVE-2021-22681] COTP CC PDU: {}".format(resp[:16].hex()))
        else:
            print_info(
                "[CVE-2021-22681] TCP/102 responded but COTP CC not confirmed. "
                "May be a different device or S7comm variant."
            )
            print_info("[CVE-2021-22681] Raw: {}".format(resp[:32].hex()))
