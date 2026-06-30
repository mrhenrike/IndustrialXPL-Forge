"""Run incorporated ics-tools vendor scripts from IXF."""

from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path
from typing import Any

from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog, IcsToolFamily


class IcsToolsRunner:
    def __init__(self) -> None:
        self.catalog = IcsToolsCatalog()

    def analyze(self, slug: str) -> dict[str, Any]:
        fam = self.catalog.get(slug)
        if not fam:
            return {"error": "Unknown ics-tool: {}".format(slug), "available": self.catalog.list_slugs()}
        scripts = sorted(str(p.relative_to(fam.vendor_path)) for p in fam.vendor_path.rglob("*.py"))[:40]
        nse = sorted(p.name for p in fam.vendor_path.glob("*.nse"))
        return {
            "slug": slug,
            "label": fam.label,
            "vendor_path": str(fam.vendor_path),
            "entry": fam.entry_script,
            "interpreter": fam.interpreter,
            "python_scripts": scripts,
            "nse_scripts": nse,
            "ixf_module": fam.ixf_module,
        }

    def run_entry(
        self,
        slug: str,
        extra_args: list[str] | None = None,
        simulate: bool = False,
        timeout: int = 120,
    ) -> dict[str, Any]:
        fam = self.catalog.get(slug)
        if not fam:
            return {"error": "Unknown ics-tool: {}".format(slug)}
        if not fam.entry_script:
            return {"error": "No entry script for {}".format(slug)}

        entry = fam.vendor_path / fam.entry_script
        if simulate:
            return {
                "simulate": True,
                "slug": slug,
                "would_run": "{} {} {}".format(fam.interpreter, entry, " ".join(extra_args or [])),
            }

        if fam.interpreter == "nmap":
            cmd = ["nmap", "--script", str(entry)] + (extra_args or [])
            cwd = str(fam.vendor_path)
        elif fam.interpreter == "data":
            return self._load_scadapass(entry)
        elif fam.interpreter == "python2":
            cmd = ["python2", str(entry)] + (extra_args or ["--help"])
            cwd = str(fam.vendor_path)
        else:
            cmd = ["python3", str(entry)] + (extra_args or ["--help"])
            cwd = str(fam.vendor_path)

        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=os.environ.copy(),
            )
            return {
                "success": r.returncode == 0,
                "cmd": " ".join(cmd),
                "stdout": (r.stdout or "")[:3000],
                "stderr": (r.stderr or "")[:1000],
                "returncode": r.returncode,
            }
        except FileNotFoundError as exc:
            return {"success": False, "error": str(exc)}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "timeout"}

    def _load_scadapass(self, csv_path: Path) -> dict[str, Any]:
        rows = []
        try:
            with csv_path.open(encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader):
                    if i >= 25:
                        break
                    rows.append(row)
            return {"success": True, "entries_preview": rows, "path": str(csv_path)}
        except OSError as exc:
            return {"success": False, "error": str(exc)}

    def compile_vendor(self, slug: str, simulate: bool = False) -> dict[str, Any]:
        """Compile .sln / native helpers where present (sixnet C# — metadata only)."""
        fam = self.catalog.get(slug)
        if not fam:
            return {"error": "Unknown ics-tool"}
        sln = list(fam.vendor_path.rglob("*.sln"))
        if simulate:
            return {"simulate": True, "solutions": [str(s) for s in sln[:5]]}
        if sln and shutil_which("msbuild"):
            try:
                r = subprocess.run(
                    ["msbuild", str(sln[0]), "/p:Configuration=Release"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=str(sln[0].parent),
                )
                return {"success": r.returncode == 0, "stdout": (r.stdout or "")[:500]}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        return {
            "success": True,
            "note": "No native compile required — run via python/nmap module",
            "vendor": str(fam.vendor_path),
        }


def shutil_which(name: str) -> bool:
    from shutil import which
    return bool(which(name))
