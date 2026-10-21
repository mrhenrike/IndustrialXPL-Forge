"""Redpoint NSE: Nmap ICS/SCADA discovery scripts orchestrator.

Automates execution of Digital Bond's Redpoint NSE scripts for
ICS device discovery and enumeration across multiple protocols.

Supported Redpoint scripts:
  - BACnet-discover-enumerate.nse (BACnet/IP devices)
  - s7-enumerate.nse (Siemens S7 PLCs)
  - enip-enumerate.nse (EtherNet/IP CIP devices)
  - modicon-info.nse (Schneider Modicon PLCs)
  - dnp3-info.nse (DNP3 outstations)
  - fox-info.nse (Tridium Niagara/Fox)
  - codesys-v2-discover.nse (CODESYS V2 runtimes)
  - omrontcp-info.nse / omronudp-info.nse (Omron FINS)
  - pcworx-info.nse (Phoenix Contact PC Worx)
  - proconos-info.nse (ProConOS runtimes)
  - cspv4-info.nse (GE SRTP/CSPv4)
  - atg-info.nse (Automatic Tank Gauge / Veeder-Root)

Requires: nmap installed on the system.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Source: Digital Bond Redpoint (BSD License)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

# Redpoint script definitions: name -> (default ports, description)
REDPOINT_SCRIPTS = {
    "BACnet-discover-enumerate": {
        "ports": "47808",
        "protocol": "udp",
        "description": "BACnet/IP device discovery and property enumeration",
    },
    "s7-enumerate": {
        "ports": "102",
        "protocol": "tcp",
        "description": "Siemens S7 PLC enumeration (module ID, SZL data)",
    },
    "enip-enumerate": {
        "ports": "44818",
        "protocol": "tcp",
        "description": "EtherNet/IP CIP device identity enumeration",
    },
    "modicon-info": {
        "ports": "502",
        "protocol": "tcp",
        "description": "Schneider Modicon PLC identification via Modbus",
    },
    "dnp3-info": {
        "ports": "20000",
        "protocol": "tcp",
        "description": "DNP3 outstation discovery",
    },
    "fox-info": {
        "ports": "1911",
        "protocol": "tcp",
        "description": "Tridium Niagara/Fox protocol discovery",
    },
    "codesys-v2-discover": {
        "ports": "1200,2455",
        "protocol": "tcp",
        "description": "CODESYS V2 runtime discovery",
    },
    "omrontcp-info": {
        "ports": "9600",
        "protocol": "tcp",
        "description": "Omron FINS/TCP device enumeration",
    },
    "omronudp-info": {
        "ports": "9600",
        "protocol": "udp",
        "description": "Omron FINS/UDP device enumeration",
    },
    "pcworx-info": {
        "ports": "1962",
        "protocol": "tcp",
        "description": "Phoenix Contact PC Worx protocol discovery",
    },
    "proconos-info": {
        "ports": "20547",
        "protocol": "tcp",
        "description": "ProConOS PLC runtime discovery",
    },
    "cspv4-info": {
        "ports": "18245",
        "protocol": "tcp",
        "description": "GE SRTP/CSPv4 protocol discovery",
    },
    "atg-info": {
        "ports": "10001",
        "protocol": "tcp",
        "description": "Automatic Tank Gauge (Veeder-Root TLS) discovery",
    },
}


@dataclass
class RedpointResult:
    """Result from a Redpoint NSE scan."""
    script: str
    target: str
    port: int
    state: str = "unknown"
    output: str = ""
    device_info: dict = field(default_factory=dict)


def find_nmap() -> str | None:
    """Locate nmap binary."""
    return shutil.which("nmap")


def find_nse_scripts(script_dir: str | None = None) -> dict[str, str]:
    """Find available Redpoint NSE scripts on disk."""
    found = {}
    search_paths = []

    if script_dir:
        search_paths.append(Path(script_dir))

    # Standard locations
    search_paths.extend([
        Path("/usr/share/nmap/scripts"),
        Path("/usr/local/share/nmap/scripts"),
        Path.home() / ".nmap" / "scripts",
    ])

    # Bundled in IndustrialXPL resources
    pkg_dir = Path(__file__).parent.parent.parent.parent / "resources" / "nse"
    if pkg_dir.exists():
        search_paths.insert(0, pkg_dir)

    for path in search_paths:
        if not path.exists():
            continue
        for name in REDPOINT_SCRIPTS:
            nse_file = path / f"{name}.nse"
            if nse_file.exists() and name not in found:
                found[name] = str(nse_file)

    return found


def run_nse_scan(nmap_bin: str, script_path: str, target: str,
                 ports: str, protocol: str = "tcp",
                 timeout: int = 30) -> list[RedpointResult]:
    """Execute a single NSE script against a target."""
    script_name = Path(script_path).stem
    scan_type = "-sU" if protocol == "udp" else "-sT"

    cmd = [
        nmap_bin, scan_type,
        "-p", ports,
        "--script", script_path,
        "-oX", "-",
        "--host-timeout", f"{timeout}s",
        "--open",
        target,
    ]

    results = []
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 15,
        )
        output = proc.stdout

        # Parse XML output for script results
        # Simple regex extraction (avoids lxml dependency)
        port_blocks = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>',
            output, re.DOTALL,
        )
        for proto, portid, block in port_blocks:
            state_match = re.search(r'state="(\w+)"', block)
            state = state_match.group(1) if state_match else "unknown"

            script_match = re.search(
                r'<script id="[^"]*" output="(.*?)"',
                block, re.DOTALL,
            )
            script_output = ""
            if script_match:
                script_output = script_match.group(1)
                script_output = script_output.replace("&#xa;", "\n").replace("&amp;", "&")

            result = RedpointResult(
                script=script_name,
                target=target,
                port=int(portid),
                state=state,
                output=script_output,
            )

            # Extract key-value pairs from NSE output
            for line in script_output.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, _, val = line.partition(":")
                    result.device_info[key.strip()] = val.strip()

            results.append(result)

    except subprocess.TimeoutExpired:
        log.warning("Nmap timeout for %s against %s", script_name, target)
    except FileNotFoundError:
        log.error("nmap binary not found at %s", nmap_bin)

    return results


class RedpointScanner(Exploit):
    """Orchestrate Digital Bond Redpoint NSE scripts for ICS discovery."""

    __info__ = {
        "name": "Redpoint NSE Scanner",
        "description": "Orchestrate Redpoint ICS/SCADA NSE scripts via Nmap",
        "authors": ["Andre Henrique (@mrhenrike)", "Digital Bond (original)"],
        "references": [
            "https://github.com/digitalbond/Redpoint",
        ],
    }

    target = OptIP("", "Target IP address")
    scripts = OptString("all", "Scripts to run (comma-separated names or 'all')")
    script_dir = OptString("", "Custom directory containing NSE scripts")
    scan_timeout = OptInteger(30, "Timeout per script execution (seconds)")

    def run(self) -> list[RedpointResult]:
        nmap_bin = find_nmap()
        if not nmap_bin:
            print_error("nmap not found in PATH. Install nmap to use Redpoint scripts.")
            return []

        available = find_nse_scripts(self.script_dir or None)
        if not available:
            print_warning("No Redpoint NSE scripts found. "
                          "Copy .nse files to ~/.nmap/scripts/ or specify --script-dir")
            return []

        print_info(f"Found {len(available)} Redpoint NSE scripts")

        if self.scripts == "all":
            to_run = available
        else:
            requested = [s.strip() for s in self.scripts.split(",")]
            to_run = {k: v for k, v in available.items() if k in requested}

        all_results = []
        target = self.target
        timeout = int(self.scan_timeout)

        for name, path in to_run.items():
            meta = REDPOINT_SCRIPTS.get(name, {})
            ports = meta.get("ports", "")
            protocol = meta.get("protocol", "tcp")
            desc = meta.get("description", "")

            print_status(f"Running {name} ({desc}) on {target}:{ports}...")
            results = run_nse_scan(nmap_bin, path, target, ports, protocol, timeout)

            for r in results:
                if r.state == "open" and r.output:
                    print_success(f"  {name}: port {r.port}/{protocol} OPEN")
                    for key, val in r.device_info.items():
                        print_info(f"    {key}: {val}")
                elif r.state == "open":
                    print_info(f"  {name}: port {r.port}/{protocol} open (no script output)")

            all_results.extend(results)

        print_status(f"Redpoint scan complete. {len(all_results)} results.")
        return all_results


MANIFEST = {
    "name": "redpoint_nse",
    "category": "scanners/ics",
    "protocols": ["bacnet", "s7comm", "enip", "modbus", "dnp3", "fox",
                  "codesys", "fins", "pcworx", "proconos", "srtp", "atg"],
    "mitre_ics": ["T0846", "T0888"],
    "source": "https://github.com/digitalbond/Redpoint",
    "license": "BSD",
    "requires": ["nmap"],
}
