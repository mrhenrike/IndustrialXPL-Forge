"""Catalog of incorporated ics-tools vendor trees."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = PKG_ROOT / "resources" / "vendor"
REFS_DIR = PKG_ROOT / "modules" / "scanners" / "refs"


@dataclass
class IcsToolFamily:
    slug: str
    label: str
    vendor_path: Path
    source_repo: str
    entry_script: str = ""
    interpreter: str = "python3"
    ixf_module: str = ""


class IcsToolsCatalog:
    LABELS = {
        "attkfinder": "ATT&CK Finder (CPS toolbox)",
        "ics-forensics-tools": "ICS Forensics Tools",
        "isf-dark-lbp": "ICSSploit / ISF (dark-lbp)",
        "isf-w3h": "ISF-W3H ICS framework",
        "redpoint": "Redpoint ICS NSE scripts",
        "scadapass": "SCADAPASS default credentials",
        "sixnet-tools": "SIXNET STA device tools",
    }

    ENTRY_SCRIPTS = {
        "attkfinder": "attkBuilder.py",
        "ics-forensics-tools": "block_logic.py",
        "isf-dark-lbp": "isf.py",
        "isf-w3h": "module/touches/plcscan/main.py",
        "redpoint": "BACnet-discover-enumerate.nse",
        "scadapass": "scadapass.csv",
        "sixnet-tools": "SIXNET tools/SIXNET_tools.py",
    }

    IXF_ROUTES = {
        "attkfinder": "scanners/ics_tools_research/ics_tools_ops",
        "ics-forensics-tools": "scanners/ics_tools_research/ics_tools_ops",
        "isf-dark-lbp": "scanners/ics_tools_research/ics_tools_ops",
        "isf-w3h": "scanners/ics_tools_research/ics_tools_ops",
        "redpoint": "scanners/ics_tools_research/ics_tools_ops",
        "scadapass": "scanners/ics_tools_research/ics_tools_ops",
        "sixnet-tools": "scanners/ics_tools_research/ics_tools_ops",
        "otscan": "scanners/ics/otscan_native",
    }

    # IXF-native tools without vendor submodule tree
    NATIVE_ICS: dict[str, dict[str, str | Path]] = {
        "otscan": {
            "label": "OTscan unified OT scanner (IXF MIT)",
            "vendor_path": PKG_ROOT / "core" / "ics" / "otscan",
            "source_repo": "IXF native (otscan-inspired)",
        },
    }

    def __init__(self) -> None:
        self._families: dict[str, IcsToolFamily] = {}

    def discover(self) -> dict[str, IcsToolFamily]:
        if self._families:
            return self._families
        for vendor_dir in sorted(VENDOR_ROOT.glob("submodules__ics-tools__*")):
            slug = vendor_dir.name.replace("submodules__ics-tools__", "")
            entry = self.ENTRY_SCRIPTS.get(slug, "")
            entry_path = vendor_dir / entry if entry else Path()
            interp = "python2" if slug in ("isf-dark-lbp",) else "python3"
            if entry.endswith(".nse"):
                interp = "nmap"
            elif entry.endswith(".csv"):
                interp = "data"
            self._families[slug] = IcsToolFamily(
                slug=slug,
                label=self.LABELS.get(slug, slug),
                vendor_path=vendor_dir,
                source_repo="submodules/ics-tools/{}".format(slug),
                entry_script=entry if entry_path.exists() else "",
                interpreter=interp,
                ixf_module=self.IXF_ROUTES.get(slug, ""),
            )
        for slug, meta in self.NATIVE_ICS.items():
            vpath = Path(meta["vendor_path"])
            if not vpath.is_dir():
                continue
            self._families[slug] = IcsToolFamily(
                slug=slug,
                label=str(meta["label"]),
                vendor_path=vpath,
                source_repo=str(meta["source_repo"]),
                entry_script="",
                interpreter="python3",
                ixf_module=self.IXF_ROUTES.get(slug, ""),
            )
        return self._families

    def list_slugs(self) -> list[str]:
        return sorted(self.discover().keys())

    def get(self, slug: str) -> IcsToolFamily | None:
        return self.discover().get(slug)
