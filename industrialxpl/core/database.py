"""IndustrialXPL Operational Database.

Extends EmbedXPL XplDatabase base for IndustrialXPL-specific usage.
Stored at ~/.industrialxpl/ixf.db

Usage::

    from industrialxpl.core.database import IxfDatabase

    db = IxfDatabase()
    db.workspace("pentest-x")
    db.add_host("192.168.1.1")
    db.add_vuln("192.168.1.1", module_path="industrialxpl...", cve_ids=["CVE-..."])
    db.add_cred("192.168.1.1", "admin", "admin")
    db.stats()

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

from pathlib import Path

# XplDatabase base from EmbedXPL (shared infrastructure)
try:
    from embedxpl.core.database import XplDatabase
except ImportError:
    # Fallback: re-implement minimal base if EmbedXPL not installed
    import sys
    _SUITE = Path(__file__).resolve().parents[5]
    if str(_SUITE / "EmbedXPL-Forge") not in sys.path:
        sys.path.insert(0, str(_SUITE / "EmbedXPL-Forge"))
    from embedxpl.core.database import XplDatabase


class IxfDatabase(XplDatabase):
    """IndustrialXPL operational database stored at ~/.industrialxpl/ixf.db.

    Domain: ICS, OT, SCADA, PLC, RTU, IED, IIoT
    """

    _DB_DIR  = Path.home() / ".industrialxpl"
    _DB_FILE = "ixf.db"
    _TOOL    = "IndustrialXPL"
