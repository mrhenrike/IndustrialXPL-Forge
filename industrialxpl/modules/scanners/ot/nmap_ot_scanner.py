"""Nmap OT/ICS Protocol Scanner Wrapper.

Wraps Nmap with OT-specific scripts and configurations heavily used in
the Daryus IoT/ICS security course. Provides structured output from:

  - nmap --script modbus-discover.nse -p 502
  - nmap --script s7-info.nse -p 102
  - nmap --script dnp3-info -p 20000
  - nmap --script bacnet-info -p 47808
  - nmap -sV -p 502,102,20000,47808,44818,4840 (full OT port sweep)

Students in the Daryus course used these commands directly. This module
provides a structured wrapper with proper output parsing.

References:
  - Daryus course commands: nmap --script modbus-discorer.nse --script-args='modbus-discover.aggressive=true' -p 502
  - Daryus Relatório 02 - student commands TSV
  - https://nmap.org/nsedoc/scripts/modbus-discover.html

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import subprocess
import shutil
import re
from dataclasses import dataclass, field
from typing import List, Optional

from industrialxpl.core.exploit import *


# Common OT/ICS ports
_OT_PORTS = {
    502: ("Modbus/TCP", "modbus-discover"),
    102: ("Siemens S7comm", "s7-info"),
    20000: ("DNP3", "dnp3-info"),
    47808: ("BACnet", "bacnet-info"),
    44818: ("EtherNet/IP", "enip-info"),
    4840: ("OPC-UA", "opc-ua-info"),
    1883: ("MQTT", None),
    5683: ("CoAP", None),
    161: ("SNMP", "snmp-info"),
    9100: ("JetDirect/PJL", "pjl-ready-message"),
}


@dataclass
class NmapOTResult:
    """Result from Nmap OT scan.

    Attributes:
        host: Scanned host.
        open_ports: Dict of port -> (service, banner).
        script_outputs: Dict of port -> script output.
        raw_output: Full nmap output.
        nmap_available: Whether nmap was found.
    """

    host: str
    open_ports: dict = field(default_factory=dict)
    script_outputs: dict = field(default_factory=dict)
    raw_output: str = ""
    nmap_available: bool = True


def _run_nmap(args: List[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run nmap with arguments.

    Args:
        args: Nmap argument list (without 'nmap' prefix).
        timeout: Command timeout in seconds.

    Returns:
        Tuple of (returncode, stdout, stderr).
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return -1, "", "nmap not found in PATH"
    try:
        result = subprocess.run(
            [nmap_bin] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "nmap timeout"
    except Exception as exc:
        return -3, "", str(exc)


def _parse_nmap_output(output: str) -> dict:
    """Parse nmap output for open ports and service info.

    Args:
        output: Nmap stdout text.

    Returns:
        Dict of port_number -> service_info.
    """
    parsed = {}
    for line in output.splitlines():
        # Match lines like "502/tcp open  modbus"
        m = re.match(r"^\s*(\d+)/(\w+)\s+open\s+(.+)$", line)
        if m:
            port = int(m.group(1))
            service = m.group(3).strip()
            parsed[port] = service
    return parsed


class Exploit(Exploit):
    """Nmap OT/ICS Protocol Scanner Wrapper.

    Wraps Nmap with OT-specific scripts for scanning industrial protocols.
    Provides the structured scanning workflow from the Daryus IoT course:
    discovery -> port scan -> protocol identification -> script output.

    Requires: nmap installed and in PATH.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Nmap OT/ICS Protocol Scanner",
        "description": (
            "Wraps Nmap with OT-specific NSE scripts to discover and fingerprint "
            "industrial control system protocols. Covers Modbus/TCP (502), "
            "S7comm (102), DNP3 (20000), BACnet (47808), EtherNet/IP (44818), "
            "OPC-UA (4840), MQTT (1883), CoAP (5683), SNMP (161), JetDirect (9100). "
            "Based on commands used in Daryus IoT/ICS security course."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://nmap.org/nsedoc/scripts/modbus-discover.html",
            "Daryus IoT Course - commands: nmap --script modbus-discover.nse -p 502",
            "nmap --script s7-info.nse --script s7-discover.nse -p 102",
        ),
        "requires": ["nmap (installed and in PATH)"],
        "daryus_commands": [
            "nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 <host>",
            "nmap -sV -p 502 192.168.1.0/24",
            "nmap -sS -sV -p- 192.168.230.133",
        ],
    }

    target = OptString("", "Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)")
    scan_mode = OptEnum(
        "full",
        "Scan mode",
        ["full", "modbus", "s7", "dnp3", "bacnet", "all_scripts", "discovery"],
    )
    aggressive = OptBool(False, "Enable aggressive scan mode (-A)")
    timeout_s = OptInteger(120, "Scan timeout in seconds")
    output_file = OptString("", "Save Nmap output to file (empty = don't save)")
    simulate = OptBool(False, "Simulate: show nmap command without executing")

    def _build_nmap_args(self) -> List[str]:
        """Build Nmap argument list based on scan_mode.

        Returns:
            List of nmap arguments.
        """
        target = str(self.target)
        mode = str(self.scan_mode)
        args = ["-v", "-n", "--open"]

        if bool(self.aggressive):
            args.append("-A")

        if mode == "modbus":
            args += [
                "--script", "modbus-discover",
                "--script-args", "modbus-discover.aggressive=true",
                "-p", "502",
            ]
        elif mode == "s7":
            args += ["--script", "s7-info,s7-discover", "-p", "102"]
        elif mode == "dnp3":
            args += ["--script", "dnp3-info", "-p", "20000"]
        elif mode == "bacnet":
            args += ["--script", "bacnet-info", "-p", "47808/udp"]
        elif mode == "all_scripts":
            port_list = ",".join(str(p) for p in _OT_PORTS.keys())
            script_list = ",".join(s for _, s in _OT_PORTS.values() if s)
            args += ["--script", script_list, "-p", port_list]
        elif mode == "discovery":
            args += ["-sV", "-p", "502,102,20000,47808,44818,4840,1883,5683,161,9100"]
        else:  # full
            args += [
                "-sS", "-sV",
                "--script", "modbus-discover,s7-info,dnp3-info,bacnet-info",
                "-p", "502,102,20000,47808,44818,4840,1883,5683,161,9100",
            ]

        if str(self.output_file):
            args += ["-oN", str(self.output_file)]

        args.append(target)
        return args

    @mute
    def check(self) -> bool:
        """Check if nmap is available.

        Returns:
            True if nmap found in PATH.
        """
        return shutil.which("nmap") is not None or bool(self.simulate)

    def run(self) -> None:
        """Execute Nmap OT scanner."""
        if not self.target:
            print_error("Set 'target' to the host, IP, or CIDR to scan.")
            return

        nmap_args = self._build_nmap_args()
        nmap_cmd = "nmap " + " ".join(nmap_args)

        if bool(self.simulate):
            print_info("[SIMULATE] Command that would be executed:")
            print_info(f"  {nmap_cmd}")
            print_info("")
            print_info("OT ports that will be scanned:")
            for port, (service, script) in _OT_PORTS.items():
                script_info = f"(script: {script})" if script else "(no OT script)"
                print_info(f"  {port}/tcp - {service} {script_info}")
            print_warning("Set simulate=false to execute. Requires nmap in PATH.")
            return

        if not shutil.which("nmap"):
            print_error("nmap not found in PATH. Install with: sudo apt install nmap")
            return

        print_status(f"Running: {nmap_cmd}")
        rc, stdout, stderr = _run_nmap(nmap_args, int(self.timeout_s))

        if rc == -1:
            print_error("nmap not found")
            return
        elif rc == -2:
            print_error(f"Scan timed out after {self.timeout_s} seconds")
            return
        elif rc < 0:
            print_error(f"nmap error: {stderr}")
            return

        open_ports = _parse_nmap_output(stdout)

        if open_ports:
            print_success(f"Open OT ports found: {len(open_ports)}")
            print_table(
                ("Port", "Service", "OT Protocol"),
                *[
                    (str(p), svc, _OT_PORTS.get(p, ("Unknown", None))[0])
                    for p, svc in open_ports.items()
                ]
            )
        else:
            print_info("No open OT ports found on target.")

        # Show script outputs if any
        if "SCRIPT RESULTS" in stdout or "modbus" in stdout.lower():
            print_info("Script output excerpt:")
            for line in stdout.splitlines():
                if any(kw in line.lower() for kw in ["modbus", "s7", "dnp3", "bacnet", "unit", "vendor"]):
                    print_info(f"  {line}")

        if str(self.output_file):
            print_success(f"Saved to: {self.output_file}")
