"""IXF NSE Manager — Nmap Scripting Engine integration.

Handles detection of Nmap installation, location of the scripts directory,
and installation of IXF OT/ICS NSE scripts into Nmap's scripts folder.

Workflow:
  1. Detect if nmap is installed (shutil.which)
  2. Locate nmap scripts directory (platform-specific + brute-force search)
  3. List IXF NSE scripts available in resources/nse_scripts/
  4. Install (copy) scripts to nmap scripts directory
  5. Run nmap --script-updatedb to register new scripts
  6. If nmap NOT installed: show IXF NSE scripts path for manual use

Platform support: Windows, Linux, macOS.
"""

import glob
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

from industrialxpl.core.exploit.printer import (
    print_error, print_info, print_status, print_success, print_warning,
    print_table,
)

# IXF NSE scripts live in this directory (relative to this file)
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
NSE_SCRIPTS_DIR = _PACKAGE_ROOT / "resources" / "nse_scripts"

# Nmap standard data directories by platform
_NMAP_SCRIPTS_CANDIDATES: dict[str, list[str]] = {
    "linux": [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/opt/nmap/share/nmap/scripts",
        "/snap/nmap/current/usr/share/nmap/scripts",
    ],
    "darwin": [
        "/usr/local/share/nmap/scripts",
        "/opt/homebrew/share/nmap/scripts",           # Homebrew ARM (Apple Silicon)
        "/usr/local/Cellar/nmap/*/share/nmap/scripts", # Homebrew Intel (glob)
        "/opt/local/share/nmap/scripts",               # MacPorts
    ],
    "win32": [
        r"C:\Program Files\Nmap\scripts",
        r"C:\Program Files (x86)\Nmap\scripts",
        r"C:\Nmap\scripts",
    ],
}


class NseManager:
    """Manages IXF NSE script installation into Nmap."""

    # ── Detection ──────────────────────────────────────────────────────────

    @staticmethod
    def find_nmap() -> Optional[str]:
        """Return the path to the nmap binary, or None if not found."""
        return shutil.which("nmap")

    @staticmethod
    def get_nmap_version() -> Optional[str]:
        """Return nmap version string, or None on failure."""
        nmap_bin = NseManager.find_nmap()
        if not nmap_bin:
            return None
        try:
            result = subprocess.run(
                [nmap_bin, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith("Nmap version"):
                    return line.strip()
        except Exception:
            pass
        return None

    @staticmethod
    def find_scripts_dir() -> Optional[Path]:
        """Locate the Nmap scripts directory.

        Strategy:
        1. Check standard platform-specific paths
        2. Derive path from nmap binary location
        3. Use glob for Homebrew-style paths
        4. Fall back to searching filesystem for *.nse files
        """
        system = sys.platform  # "win32", "darwin", "linux"
        candidates = _NMAP_SCRIPTS_CANDIDATES.get(
            system,
            _NMAP_SCRIPTS_CANDIDATES["linux"],
        )

        # Add binary-derived path
        nmap_bin = shutil.which("nmap")
        if nmap_bin:
            bin_path = Path(nmap_bin).resolve()
            # e.g. /usr/bin/nmap → /usr/share/nmap/scripts
            for parent_levels in range(1, 4):
                ancestor = bin_path
                for _ in range(parent_levels + 1):
                    ancestor = ancestor.parent
                derived = ancestor / "share" / "nmap" / "scripts"
                if str(derived) not in candidates:
                    candidates.append(str(derived))
            # Windows: C:\Program Files (x86)\Nmap\nmap.exe → ..\scripts
            if sys.platform == "win32":
                win_scripts = str(bin_path.parent / "scripts")
                if win_scripts not in candidates:
                    candidates.append(win_scripts)

        # Check each candidate (expand globs for Homebrew paths)
        for candidate in candidates:
            # Handle glob patterns (e.g. /usr/local/Cellar/nmap/*/share/...)
            if "*" in candidate:
                matches = glob.glob(candidate)
                for match in sorted(matches, reverse=True):  # newest version first
                    p = Path(match)
                    if p.is_dir():
                        return p
            else:
                p = Path(candidate)
                if p.is_dir():
                    return p

        # Last resort: locate/find *.nse on the filesystem
        scripts_dir = NseManager._locate_nse_dir_via_find()
        if scripts_dir:
            return scripts_dir

        return None

    @staticmethod
    def _locate_nse_dir_via_find() -> Optional[Path]:
        """Use OS tools to find the nmap scripts directory."""
        if sys.platform == "win32":
            # Use where.exe + dir to find nmap scripts on Windows
            nmap_bin = shutil.which("nmap")
            if nmap_bin:
                scripts = Path(nmap_bin).parent / "scripts"
                if scripts.is_dir():
                    return scripts
            # Try PROGRAMFILES environment variable
            for env_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
                base = os.environ.get(env_var, "")
                if base:
                    p = Path(base) / "Nmap" / "scripts"
                    if p.is_dir():
                        return p
            return None

        else:
            # Linux/macOS: use locate or find
            for cmd in [
                ["locate", "-l", "1", "-r", "nmap/scripts$"],
                ["find", "/usr", "/opt", "-name", "*.nse", "-maxdepth", "6", "-quit"],
            ]:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=15,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        found = result.stdout.strip().splitlines()[0]
                        p = Path(found)
                        if p.is_file():
                            p = p.parent
                        if p.is_dir():
                            return p
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            return None

    # ── Script listing ─────────────────────────────────────────────────────

    @staticmethod
    def list_ixf_scripts() -> list[Path]:
        """Return list of .nse files in IXF resources."""
        if not NSE_SCRIPTS_DIR.is_dir():
            return []
        return sorted(NSE_SCRIPTS_DIR.glob("*.nse"))

    @staticmethod
    def list_installed(scripts_dir: Path) -> list[str]:
        """Return names of IXF scripts already installed in nmap scripts dir."""
        ixf_names = {s.name for s in NseManager.list_ixf_scripts()}
        installed = []
        for name in ixf_names:
            if (scripts_dir / name).exists():
                installed.append(name)
        return sorted(installed)

    # ── Installation ────────────────────────────────────────────────────────

    @staticmethod
    def install(
        scripts_dir: Optional[Path] = None,
        force: bool = False,
    ) -> dict:
        """Install IXF NSE scripts into Nmap scripts directory.

        Returns a result dict with keys:
          success   : bool
          installed : list[str] — scripts successfully installed
          skipped   : list[str] — scripts already present (not force)
          errors    : list[str] — installation failures
          scripts_dir: str
        """
        result = {
            "success": False,
            "installed": [],
            "skipped": [],
            "errors": [],
            "scripts_dir": "",
        }

        # Auto-detect scripts dir if not provided
        if scripts_dir is None:
            scripts_dir = NseManager.find_scripts_dir()
        if scripts_dir is None:
            result["errors"].append(
                "Nmap scripts directory not found. "
                "Install Nmap first: https://nmap.org/download"
            )
            return result

        result["scripts_dir"] = str(scripts_dir)
        ixf_scripts = NseManager.list_ixf_scripts()

        if not ixf_scripts:
            result["errors"].append("No IXF NSE scripts found in resources/nse_scripts/")
            return result

        for src in ixf_scripts:
            dst = scripts_dir / src.name
            if dst.exists() and not force:
                result["skipped"].append(src.name)
                continue
            try:
                shutil.copy2(str(src), str(dst))
                # Ensure readable (Linux: 644)
                if sys.platform != "win32":
                    dst.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                result["installed"].append(src.name)
            except PermissionError:
                result["errors"].append(
                    f"{src.name}: PermissionError — "
                    "run as administrator (Windows) or with sudo (Linux/macOS)"
                )
            except Exception as exc:
                result["errors"].append(f"{src.name}: {exc}")

        if result["installed"]:
            # Run nmap --script-updatedb to register new scripts
            NseManager._run_updatedb()

        result["success"] = len(result["errors"]) == 0
        return result

    @staticmethod
    def _run_updatedb() -> None:
        """Run nmap --script-updatedb silently."""
        nmap_bin = NseManager.find_nmap()
        if not nmap_bin:
            return
        try:
            subprocess.run(
                [nmap_bin, "--script-updatedb"],
                capture_output=True, timeout=30,
            )
        except Exception:
            pass

    # ── Rich output helpers ─────────────────────────────────────────────────

    # ── Entry point ────────────────────────────────────────────────────────

    @staticmethod
    def status_report() -> None:
        """Print a rich status report of IXF NSE scripts to the terminal."""
        nmap_bin = NseManager.find_nmap()
        ixf_scripts = NseManager.list_ixf_scripts()
        scripts_dir = NseManager.find_scripts_dir()

        print_status("[NSE] IndustrialXPL-Forge Nmap Script Status")
        print_info(f"IXF NSE scripts available : {len(ixf_scripts)}")
        print_info(f"IXF NSE scripts path      : {NSE_SCRIPTS_DIR}")

        print_info("")
        if nmap_bin:
            version = NseManager.get_nmap_version() or "Nmap (version unknown)"
            print_success(f"Nmap binary : {nmap_bin}")
            print_success(f"Version     : {version}")
        else:
            print_error("Nmap NOT installed — download from https://nmap.org/download")

        if scripts_dir:
            print_success(f"Scripts dir : {scripts_dir}")
            installed = NseManager.list_installed(scripts_dir)
            not_installed = [s.name for s in ixf_scripts if s.name not in installed]
            print_info(f"IXF scripts installed : {len(installed)}/{len(ixf_scripts)}")
        else:
            not_installed = [s.name for s in ixf_scripts]
            print_warning("Nmap scripts directory not found")

        print_info("")

        # Table of all IXF scripts
        rows = []
        for script in ixf_scripts:
            if scripts_dir:
                status = "INSTALLED" if (scripts_dir / script.name).exists() else "not installed"
            else:
                status = "nmap not installed"
            rows.append((script.name, status))

        if rows:
            print_table(
                ["Script", "Status"],
                rows,
                title="IXF NSE Scripts for OT/ICS",
            )

        if not_installed and not nmap_bin:
            print_info("")
            print_warning(
                "Nmap not detected. Install Nmap to use these scripts.\n"
                f"Scripts are stored in IXF at: {NSE_SCRIPTS_DIR}\n"
                "Once Nmap is installed, run: ixf > nse install"
            )
        elif not_installed:
            print_info("")
            print_warning(
                f"{len(not_installed)} script(s) not yet installed.\n"
                "Run: ixf > nse install"
            )


def _nse_install_entry() -> None:
    """Entry point for ixf-nse-install console script."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
    from tools import nse_install
    nse_install.main()
