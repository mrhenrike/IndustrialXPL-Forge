"""Module index builder for MITRE ATT&CK for ICS technique mapping.

Scans all IXF modules at startup and builds:
    TECHNIQUE_INDEX: { "T0843": ["exploits.plc.siemens.s7_1200_plc_control", ...] }
    TACTIC_INDEX:    { "TA0106": ["exploits.plc.siemens.s7_1200_plc_control", ...] }
"""

import importlib
import logging
from typing import Optional

from industrialxpl.core.mitre.tactics import TACTIC_TIDS, TACTICS

logger = logging.getLogger(__name__)

TECHNIQUE_INDEX: dict[str, list[str]] = {}
TACTIC_INDEX: dict[str, list[str]] = {}

_built = False


def build_index(module_paths: Optional[list] = None) -> None:
    """Build the MITRE index from module __info__["mitre_techniques"].

    Args:
        module_paths: Dotted module path list (from index_modules()).
                      If None, imports from utils on first call.
    """
    global _built, TECHNIQUE_INDEX, TACTIC_INDEX
    if _built and module_paths is None:
        return

    TECHNIQUE_INDEX.clear()
    TACTIC_INDEX.clear()

    if module_paths is None:
        from industrialxpl.core.exploit.utils import index_modules
        module_paths = index_modules()

    # Build reverse map: TID -> tactic
    tid_to_tactic: dict[str, str] = {}
    for tac_id, tids in TACTIC_TIDS.items():
        for t in tids:
            tid_to_tactic[t] = tac_id

    for mod_path in module_paths:
        full = "industrialxpl.modules.{}".format(mod_path)
        try:
            mod = importlib.import_module(full)
            cls = getattr(mod, "Exploit", None) or getattr(mod, "Scanner", None) or getattr(mod, "Assessment", None)
            if cls is None:
                continue
            info = getattr(cls, "_{cls}__info__".format(cls=cls.__name__), {})
            techniques: list = info.get("mitre_techniques", [])
            for raw_tid in techniques:
                # Handle "T0843.001" or "T0843 Program Download" formats
                tid = raw_tid.split()[0].split("—")[0].strip()
                TECHNIQUE_INDEX.setdefault(tid, [])
                if mod_path not in TECHNIQUE_INDEX[tid]:
                    TECHNIQUE_INDEX[tid].append(mod_path)
                tac = tid_to_tactic.get(tid)
                if tac:
                    TACTIC_INDEX.setdefault(tac, [])
                    if mod_path not in TACTIC_INDEX[tac]:
                        TACTIC_INDEX[tac].append(mod_path)
        except Exception as exc:
            logger.debug("MITRE index: skip %s — %s", mod_path, exc)

    _built = True
