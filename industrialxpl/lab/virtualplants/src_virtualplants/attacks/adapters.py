"""Allowlisted adapters for external OT lab tools.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import List, Optional, Sequence

from . import AttackRecord
from ..core.safety import LabSafetyError, iter_safe_argv


@dataclass(frozen=True)
class AdapterPlan:
    """Resolved executable plus argument vector."""

    executable: str
    argv: List[str]
    available: bool
    reason: str = ""


def _which_any(names: Sequence[str]) -> Optional[str]:
    """Return the first executable found on PATH."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _fill_template(record: AttackRecord, host: str, port: int) -> List[str]:
    """Substitute host/port placeholders without using a shell."""
    filled: List[str] = []
    for item in record.argv_template:
        filled.append(item.replace("{host}", host).replace("{port}", str(port)))
    return list(iter_safe_argv(filled))


def plan_adapter(record: AttackRecord, host: str, port: int) -> AdapterPlan:
    """Build a subprocess plan for a catalog record."""
    argv = _fill_template(record, host, port)
    adapter = record.adapter
    if adapter in {"internal-modbus", "internal-http", "internal-tcp"}:
        return AdapterPlan(executable="internal", argv=argv, available=True)

    if adapter == "modbus-cli":
        exe = _which_any(("modbus", "modbus-cli"))
        if not exe:
            return AdapterPlan("modbus", argv, False, "modbus-cli is not installed")
        return AdapterPlan(exe, argv, True)

    if adapter == "embedxpl":
        exe = _which_any(("embedxpl", "exf.py"))
        if not exe:
            sibling = os.environ.get("EMBEDXPL_BIN", "")
            if sibling and os.path.isfile(sibling):
                exe = sibling
        if not exe:
            return AdapterPlan("embedxpl", argv, False, "EmbedXPL-Forge is not on PATH")
        if record.persona not in {"plant", "plc", "scada", "protocol", "gateway"}:
            raise LabSafetyError("EmbedXPL adapter rejected for persona %s" % record.persona)
        return AdapterPlan(exe, argv, True)

    if adapter == "metasploit":
        exe = _which_any(("msfconsole",))
        if not exe:
            return AdapterPlan("msfconsole", argv, False, "Metasploit is not installed")
        return AdapterPlan(exe, argv, True)

    if adapter == "routersploit":
        if record.persona != "gateway":
            raise LabSafetyError("RouterSploit is only allowed for gateway personas")
        exe = _which_any(("rsf", "routersploit"))
        if not exe:
            return AdapterPlan("rsf", argv, False, "RouterSploit is not installed")
        return AdapterPlan(exe, argv, True)

    if adapter == "pret":
        if record.persona != "printer":
            raise LabSafetyError("PRET/PrinterXPL is only allowed for printer personas")
        exe = _which_any(("pxf.py", "pret"))
        if not exe:
            return AdapterPlan("pxf.py", argv, False, "Printer toolkit is not installed")
        return AdapterPlan(exe, argv, True)

    raise LabSafetyError("unknown adapter")
