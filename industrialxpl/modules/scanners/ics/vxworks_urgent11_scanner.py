"""VxWorks URGENT/11 Vulnerability Scanner (NozomiNetworks / Armis Research).

Detects devices running VxWorks 6.5-6.x that may be vulnerable to URGENT/11 —
11 critical vulnerabilities in the IPnet TCP/IP stack used by VxWorks RTOS.
Affects PLCs, RTUs, HMIs, safety controllers, network devices.

Source: github.com/NozomiNetworks/urgent-11 (Nmap NSE)
NSE: resources/nse/vxworks_urgent11.nse
Author: NozomiNetworks/Armis (original) | Andre Henrique (@mrhenrike) — IXF wrapper
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from industrialxpl.core.exploit import *

_NSE_SCRIPT = Path(__file__).resolve().parents[3] / "resources" / "nse" / "vxworks_urgent11.nse"

# 11 URGENT/11 CVEs
_URGENT11_CVES = {
    "CVE-2019-12255": "TCP Urgent Pointer = 0 leads to integer underflow (RCE)",
    "CVE-2019-12256": "Stack overflow in IPv4 options parsing (RCE)",
    "CVE-2019-12257": "Heap overflow in DHCP Offer/ACK parsing (RCE)",
    "CVE-2019-12258": "DoS via malformed TCP options",
    "CVE-2019-12259": "DoS via NULL dereference in IGMP parsing",
    "CVE-2019-12260": "TCP Urgent Pointer confusion via malformed TCP AO option (RCE)",
    "CVE-2019-12261": "TCP Urgent Pointer confusion during connect() (RCE)",
    "CVE-2019-12262": "Unsolicited Reverse ARP replies handling",
    "CVE-2019-12263": "TCP Urgent Pointer race condition (RCE)",
    "CVE-2019-12264": "Logical flaw in IPv4 assignment by DHCP client",
    "CVE-2019-12265": "IGMP information leak via IGMPv3 membership report",
}

# VxWorks versions with known URGENT/11 exposure (6.5 ≤ ver < 7.0)
_VULNERABLE_VERSIONS = re.compile(r"VxWorks\s+(6\.[5-9][\d.]*)", re.IGNORECASE)


class Exploit(BaseExploit):
    """VxWorks URGENT/11 Scanner — NozomiNetworks urgent-11 NSE.

    Scans for devices running vulnerable VxWorks versions via FTP banner
    fingerprinting. VxWorks versions 6.5–6.x are affected by 11 critical
    vulnerabilities (6 RCE, 5 DoS/Info) in the IPnet TCP/IP stack.
    Widely deployed in ICS/OT: PLCs, RTUs, HMIs, safety controllers.
    """

    __info__ = {
        "name": "VxWorks URGENT/11 Scanner (NozomiNetworks urgent-11)",
        "description": (
            "Detects VxWorks devices vulnerable to URGENT/11 (CVE-2019-12255 to 12265) "
            "via FTP banner analysis on port 21. Affected: VxWorks 6.5 <= v < 7.0. "
            "6 RCE vulnerabilities + 5 DoS/Info leak in IPnet TCP/IP stack. "
            "Commonly found in PLCs, RTUs, HMIs, medical devices, network equipment."
        ),
        "authors": (
            "NozomiNetworks / Armis Research (urgent-11 NSE)",
            "Andre Henrique (@mrhenrike) — IXF integration",
        ),
        "references": (
            "https://github.com/NozomiNetworks/urgent-11",
            "https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/",
            "resources/nse/vxworks_urgent11.nse",
        ),
        "devices": (
            "VxWorks 6.5 - 6.x PLCs",
            "RTUs with VxWorks RTOS",
            "HMIs running VxWorks 6.5-6.x",
            "Safety controllers (pre-VxWorks 7)",
        ),
        "impact": "READ",
        "mitre_techniques": ["T0846", "T0888"],
        "malware_family": None,
        "cve": list(_URGENT11_CVES.keys()),
        "severity": "CRITICAL",
    }

    target   = OptIP("", "Target IP to scan for VxWorks FTP banner")
    port     = OptPort(21, "FTP port for VxWorks banner check")
    timeout  = OptFloat(5.0, "Connection timeout")
    simulate = OptBool(True, "Simulate mode")

    def check(self) -> bool:
        if self.simulate:
            return True
        if not shutil.which("nmap"):
            print_error("nmap not found — install nmap to run NSE scripts")
            return False
        if not _NSE_SCRIPT.exists():
            print_error(f"NSE script not found: {_NSE_SCRIPT}")
            return False
        return True

    def run(self) -> None:
        if self.simulate:
            print_status(f"[SIMULATE] VxWorks URGENT/11 scan @ {self.target}:{self.port}")
            print_status()
            print_status("  URGENT/11 — 11 CVEs in VxWorks 6.5 ≤ ver < 7.0 IPnet stack:")
            for cve, desc in _URGENT11_CVES.items():
                severity = "(RCE)" if "RCE" in desc else "(DoS/Info)"
                print_status(f"    [{cve}] {severity} {desc}")
            print_status()
            print_status(f"  Command: nmap -p 21 -Pn -n --script {_NSE_SCRIPT} {self.target}")
            print_status("  Detection: FTP banner contains 'VxWorks 6.x' string")
            print_status()
            print_status("  Mitigation: Upgrade to VxWorks 7+ or apply Wind River patches")
            print_status("  Ref: https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/")
            return

        if not self.check():
            return

        print_status(f"Scanning {self.target}:{self.port} for VxWorks URGENT/11...")

        cmd = [
            "nmap", "-p", str(self.port),
            "-Pn", "-n",
            "--script", str(_NSE_SCRIPT),
            self.target,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout

            # Parse results
            ver_match = _VULNERABLE_VERSIONS.search(output)
            if ver_match:
                ver = ver_match.group(1)
                print_error(f"VULNERABLE VxWorks {ver} detected on {self.target}:{self.port}!")
                print_status("  Applicable URGENT/11 CVEs (6 RCE + 5 DoS/Info):")
                for cve, desc in _URGENT11_CVES.items():
                    print_status(f"    {cve}: {desc}")
            elif "VxWorks" in output:
                print_status("  VxWorks detected — check version manually")
            else:
                print_success("  No VxWorks FTP banner detected")

            # Print raw nmap output
            for line in output.split("\n"):
                if line.strip() and not line.startswith("Starting"):
                    print_status(f"  {line}")

        except subprocess.TimeoutExpired:
            print_error("Scan timed out")
        except Exception as e:
            print_error(f"Scan error: {e}")
