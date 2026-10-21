"""Conpot ICS Honeypot Deployer and Manager.

Deploys and manages Conpot honeypot instances for ICS deception
and adversary intelligence collection. Supports automated template
generation for multiple ICS protocols.

Conpot emulates:
  - Modbus TCP slave
  - S7comm (Siemens S7-200)
  - BACnet/IP device
  - EtherNet/IP CIP device
  - IEC 60870-5-104 slave
  - IPMI BMC
  - Guardian AST (tank gauge)
  - HTTP/HTTPS (HMI web interfaces)
  - SNMP (ICS MIBs)
  - FTP/TFTP (firmware upload)

Requires: conpot (pip install conpot)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Source: Conpot by MushOrg (GPL-2.0)
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

try:
    import conpot
    HAS_CONPOT = True
except ImportError:
    HAS_CONPOT = False


# ---------------------------------------------------------------------------
# Conpot template configurations
# ---------------------------------------------------------------------------

CONPOT_TEMPLATES = {
    "default": {
        "description": "Generic ICS device (Modbus + S7 + HTTP + SNMP)",
        "protocols": ["modbus", "s7comm", "http", "snmp"],
    },
    "guardian_ast": {
        "description": "Veeder-Root Guardian AST tank gauge",
        "protocols": ["guardian_ast", "http"],
    },
    "iec104": {
        "description": "IEC 60870-5-104 slave device",
        "protocols": ["iec104", "http"],
    },
    "ipmi": {
        "description": "IPMI BMC (Baseboard Management Controller)",
        "protocols": ["ipmi", "http"],
    },
    "kamstrup_382": {
        "description": "Kamstrup 382 smart meter",
        "protocols": ["kamstrup_management", "kamstrup_meter"],
    },
}

# Default Modbus register map for honeypot
DEFAULT_MODBUS_SLAVE = {
    "device_info": {
        "vendor": "Schneider Electric",
        "product": "Modicon M340",
        "version": "V3.20",
    },
    "holding_registers": {
        "0": {"value": 0, "description": "System status"},
        "1": {"value": 100, "description": "Temperature setpoint"},
        "2": {"value": 50, "description": "Pressure setpoint"},
        "100": {"value": 1, "description": "Run/Stop"},
    },
    "coils": {
        "0": {"value": True, "description": "Output 1"},
        "1": {"value": False, "description": "Output 2"},
    },
}


@dataclass
class ConpotInstance:
    """Represents a running Conpot honeypot instance."""
    template: str
    bind_ip: str
    pid: int = 0
    log_dir: str = ""
    protocols: list[str] = field(default_factory=list)
    start_time: float = 0.0
    process: Optional[subprocess.Popen] = None


def generate_modbus_template(config: dict, output_dir: str) -> str:
    """Generate a custom Modbus slave template for Conpot."""
    template_dir = Path(output_dir) / "custom_modbus"
    template_dir.mkdir(parents=True, exist_ok=True)

    # Write template.xml
    device = config.get("device_info", {})
    vendor = device.get("vendor", "Generic")
    product = device.get("product", "PLC")

    template_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<conpot_template name="custom_modbus" description="Custom Modbus honeypot">
  <core>
    <databus>
      <key_value_mappings>
        <key name="vendor">{vendor}</key>
        <key name="product_code">{product}</key>
      </key_value_mappings>
    </databus>
  </core>
  <protocols>
    <modbus enabled="true" host="0.0.0.0" port="502"/>
    <http enabled="true" host="0.0.0.0" port="80"/>
    <s7comm enabled="true" host="0.0.0.0" port="102"/>
    <snmp enabled="true" host="0.0.0.0" port="161"/>
  </protocols>
</conpot_template>"""

    template_file = template_dir / "template.xml"
    template_file.write_text(template_xml)
    return str(template_dir)


def start_conpot(template: str = "default", bind_ip: str = "0.0.0.0",
                 log_dir: str = "/tmp/conpot-logs",
                 custom_template_dir: str = "") -> Optional[ConpotInstance]:
    """Start a Conpot honeypot instance."""
    if not HAS_CONPOT:
        conpot_bin = "conpot"
    else:
        conpot_bin = sys.executable + " -m conpot"

    Path(log_dir).mkdir(parents=True, exist_ok=True)

    cmd = f"{conpot_bin} --template {template} --host {bind_ip} --logfile {log_dir}/conpot.log"
    if custom_template_dir:
        cmd = f"{conpot_bin} --template {custom_template_dir} --host {bind_ip} --logfile {log_dir}/conpot.log"

    try:
        proc = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(3)

        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            log.error("Conpot failed to start: %s", stderr)
            return None

        instance = ConpotInstance(
            template=template,
            bind_ip=bind_ip,
            pid=proc.pid,
            log_dir=log_dir,
            protocols=CONPOT_TEMPLATES.get(template, {}).get("protocols", []),
            start_time=time.time(),
            process=proc,
        )
        return instance

    except FileNotFoundError:
        log.error("conpot binary not found. Install: pip install conpot")
        return None
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        log.error("Failed to start conpot: %s", e)
        return None


def stop_conpot(instance: ConpotInstance) -> bool:
    """Stop a running Conpot instance."""
    if instance.process:
        try:
            instance.process.terminate()
            instance.process.wait(timeout=10)
            return True
        except subprocess.TimeoutExpired:
            instance.process.kill()
            return True
        except (OSError, subprocess.SubprocessError):
            pass
    if instance.pid:
        try:
            os.kill(instance.pid, signal.SIGTERM)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False
    return False


def read_conpot_logs(log_dir: str, last_n: int = 50) -> list[str]:
    """Read recent Conpot log entries for attack intelligence."""
    log_file = Path(log_dir) / "conpot.log"
    if not log_file.exists():
        return []
    lines = log_file.read_text().splitlines()
    return lines[-last_n:]


# ---------------------------------------------------------------------------
# Exploit module
# ---------------------------------------------------------------------------

class ConpotDeployer(Exploit):
    """Deploy and manage Conpot ICS honeypots for deception."""

    __info__ = {
        "name": "Conpot Deployer",
        "description": "ICS honeypot deployment and management using Conpot",
        "authors": ["Andre Henrique (@mrhenrike)", "MushOrg (Conpot)"],
        "references": [
            "https://github.com/mushorg/conpot",
            "MITRE D3FEND D3-DEC (Decoy Environment)",
        ],
    }

    action = OptString("deploy", "Action: deploy, stop, status, logs")
    template = OptString("default", "Conpot template: default, guardian_ast, iec104, ipmi")
    bind_ip = OptString("0.0.0.0", "IP address to bind honeypot")
    log_dir = OptString("/tmp/conpot-logs", "Directory for honeypot logs")
    custom_vendor = OptString("", "Custom vendor name for Modbus template")
    custom_product = OptString("", "Custom product name for Modbus template")

    _instance: Optional[ConpotInstance] = None

    def run(self) -> dict:
        action = self.action.lower()

        if action == "deploy":
            return self._deploy()
        elif action == "stop":
            return self._stop()
        elif action == "status":
            return self._status()
        elif action == "logs":
            return self._logs()
        else:
            print_error(f"Unknown action: {action}")
            return {"error": f"Unknown action: {action}"}

    def _deploy(self) -> dict:
        if not HAS_CONPOT:
            print_warning("conpot not installed. Install: pip install conpot")
            print_info("Generating template configuration only...")

        template = self.template
        if template not in CONPOT_TEMPLATES and not self.custom_vendor:
            print_error(f"Unknown template: {template}. Available: {', '.join(CONPOT_TEMPLATES)}")
            return {"error": "Unknown template"}

        if self.custom_vendor:
            config = {
                "device_info": {
                    "vendor": self.custom_vendor,
                    "product": self.custom_product or "PLC",
                },
            }
            template_dir = generate_modbus_template(config, self.log_dir)
            print_success(f"Custom template generated at {template_dir}")

            if HAS_CONPOT:
                self._instance = start_conpot(
                    custom_template_dir=template_dir,
                    bind_ip=self.bind_ip,
                    log_dir=self.log_dir,
                )
        else:
            if HAS_CONPOT:
                self._instance = start_conpot(
                    template=template,
                    bind_ip=self.bind_ip,
                    log_dir=self.log_dir,
                )

        if self._instance:
            print_success(f"Conpot honeypot deployed (PID {self._instance.pid})")
            print_info(f"Template: {template}")
            print_info(f"Bind: {self.bind_ip}")
            print_info(f"Logs: {self.log_dir}")
            return {"status": "running", "pid": self._instance.pid}

        tmpl = CONPOT_TEMPLATES.get(template, {})
        print_info(f"Template info: {tmpl.get('description', template)}")
        print_info(f"Protocols: {', '.join(tmpl.get('protocols', []))}")
        return {"status": "template_only", "template": template}

    def _stop(self) -> dict:
        if self._instance:
            if stop_conpot(self._instance):
                print_success("Conpot honeypot stopped")
                return {"status": "stopped"}
        print_warning("No active honeypot instance to stop")
        return {"status": "not_running"}

    def _status(self) -> dict:
        if self._instance and self._instance.process:
            if self._instance.process.poll() is None:
                uptime = time.time() - self._instance.start_time
                print_success(f"Conpot running (PID {self._instance.pid}, uptime {uptime:.0f}s)")
                return {"status": "running", "pid": self._instance.pid, "uptime": uptime}
        print_info("No active honeypot instance")
        return {"status": "not_running"}

    def _logs(self) -> dict:
        entries = read_conpot_logs(self.log_dir)
        if entries:
            print_status(f"Last {len(entries)} log entries:")
            for line in entries:
                print_info(f"  {line}")
        else:
            print_info("No log entries found")
        return {"entries": len(entries)}


MANIFEST = {
    "name": "conpot_deployer",
    "category": "deception",
    "protocols": ["modbus", "s7comm", "bacnet", "enip", "iec104", "http", "snmp"],
    "mitre_ics": ["T0817"],
    "source": "https://github.com/mushorg/conpot",
    "license": "GPL-2.0",
    "requires": ["conpot"],
}
