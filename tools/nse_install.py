#!/usr/bin/env python3
"""IXF NSE Install — Install IXF OT/ICS Nmap scripts.

Standalone installer for IndustrialXPL-Forge NSE scripts.
Can be run directly without the IXF interactive shell.

Usage:
    python tools/nse_install.py               # Status check + install prompt
    python tools/nse_install.py --install     # Install all IXF NSE scripts
    python tools/nse_install.py --force       # Reinstall even if already present
    python tools/nse_install.py --list        # List available IXF scripts
    python tools/nse_install.py --status      # Show Nmap + scripts status
    python tools/nse_install.py --scripts-dir /custom/path  # Custom scripts dir

Or via pip-installed package:
    ixf-nse-install              # Entry point (if installed via pip)

Validation:
  1. Checks if Nmap is installed (shutil.which)
  2. Locates Nmap scripts directory automatically
  3. Lists IXF scripts to install
  4. Copies .nse files to Nmap scripts dir
  5. Runs: nmap --script-updatedb
  6. If Nmap NOT installed: shows IXF scripts path for manual use
"""

import argparse
import sys
from pathlib import Path

# Allow running from repo root without installing package
_TOOLS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TOOLS_DIR.parent
sys.path.insert(0, str(_REPO_ROOT))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    _HAS_RICH = True
    console = Console()
except ImportError:
    _HAS_RICH = False
    console = None

from industrialxpl.core.nse.nse_manager import NseManager, NSE_SCRIPTS_DIR


def _print(msg: str, style: str = "") -> None:
    if _HAS_RICH and console:
        console.print(msg, style=style)
    else:
        print(msg)


def _panel(title: str, content: str, style: str = "cyan") -> None:
    if _HAS_RICH and console:
        console.print(Panel(content, title=title, border_style=style))
    else:
        print(f"\n=== {title} ===")
        print(content)


def show_banner() -> None:
    banner = r"""
  _____ __  __ _____     _   _  ____  _____   _____           _        _ _
 |_ _\ \ \/ /|  ___|   | \ | |/ ___|| ____| |_   _|__   ___ | |___  _(_) |
  | |  \  / | |_      |  \| |\___ \|  _|     | |/ _ \ / _ \| / __| (_) ____|
  | |  /  \ |  _|     | |\  | ___) | |___    | | (_) | (_) | \__ \ _ | |
 |___|/_/\_\|_|       |_| \_||____/|_____|   |_|\___/ \___/|_|___/(_)|_|

  IndustrialXPL-Forge NSE Installer
  OT/ICS Nmap Scripts for Industrial Security Assessment
    """
    _print(banner, "bold cyan")


def cmd_status() -> None:
    """Show Nmap + IXF NSE status."""
    NseManager.status_report()

    nmap_bin = NseManager.find_nmap()
    if not nmap_bin:
        _print("\n[bold yellow]Nmap Installation Instructions:[/bold yellow]")
        _print("  Linux:   sudo apt install nmap   OR   sudo dnf install nmap")
        _print("  macOS:   brew install nmap        OR   https://nmap.org/download")
        _print("  Windows: https://nmap.org/download")
        _print(f"\nIXF NSE scripts location: {NSE_SCRIPTS_DIR}")
        _print("Once Nmap is installed, run: python tools/nse_install.py --install")


def cmd_list() -> None:
    """List all IXF NSE scripts."""
    scripts = NseManager.list_ixf_scripts()
    if not scripts:
        _print("[red]No IXF NSE scripts found.[/red]")
        return

    if _HAS_RICH and console:
        table = Table(title="IXF NSE Scripts for OT/ICS", box=box.SIMPLE_HEAVY)
        table.add_column("Script", style="cyan")
        table.add_column("Size", style="dim")
        table.add_column("Description (first line)")
        for s in scripts:
            size = f"{s.stat().st_size:,} B"
            # Read description from first non-blank line of the file
            desc = ""
            try:
                for line in s.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip().strip('"').strip("[[").strip("]]").strip()
                    if line and not line.startswith("--") and len(line) > 10:
                        desc = line[:70]
                        break
            except Exception:
                pass
            table.add_row(s.name, size, desc)
        console.print(table)
    else:
        print(f"\nIXF NSE Scripts ({len(scripts)} total):")
        for s in scripts:
            print(f"  {s.name}")

    _print(f"\nLocation: {NSE_SCRIPTS_DIR}")


def cmd_install(force: bool = False, scripts_dir_override: str = "") -> None:
    """Install IXF NSE scripts into Nmap."""
    # Check nmap first
    nmap_bin = NseManager.find_nmap()
    if not nmap_bin:
        _print("[bold red]ERROR: Nmap is not installed on this system.[/bold red]")
        _print("")
        _print("Install Nmap first:")
        _print("  Linux:   sudo apt install nmap")
        _print("  macOS:   brew install nmap")
        _print("  Windows: https://nmap.org/download")
        _print("")
        _print(f"[bold yellow]IXF NSE scripts are available at:[/bold yellow]")
        _print(f"  {NSE_SCRIPTS_DIR}")
        _print("")
        _print("After installing Nmap, copy the .nse files manually to:")
        _print("  Linux:   /usr/share/nmap/scripts/")
        _print("  macOS:   /usr/local/share/nmap/scripts/")
        _print("  Windows: C:\\Program Files (x86)\\Nmap\\scripts\\")
        _print("Then run: nmap --script-updatedb")
        sys.exit(1)

    version = NseManager.get_nmap_version()
    _print(f"[green]Nmap found:[/green] {nmap_bin}")
    if version:
        _print(f"[green]Version:[/green] {version}")

    # Determine scripts dir
    scripts_dir = None
    if scripts_dir_override:
        scripts_dir = Path(scripts_dir_override)
        if not scripts_dir.is_dir():
            _print(f"[red]ERROR: Provided scripts dir not found: {scripts_dir}[/red]")
            sys.exit(1)
    else:
        scripts_dir = NseManager.find_scripts_dir()

    if scripts_dir is None:
        _print("[red]ERROR: Nmap scripts directory not found.[/red]")
        _print("Provide it manually: --scripts-dir /path/to/nmap/scripts")
        _print(f"\nIXF NSE scripts available at: {NSE_SCRIPTS_DIR}")
        sys.exit(1)

    _print(f"[green]Nmap scripts dir:[/green] {scripts_dir}")

    # List what will be installed
    ixf_scripts = NseManager.list_ixf_scripts()
    already = NseManager.list_installed(scripts_dir)
    to_install = [s for s in ixf_scripts if s.name not in already or force]
    skip_count = len(ixf_scripts) - len(to_install)

    _print(f"\nIXF scripts available : {len(ixf_scripts)}")
    _print(f"Already installed     : {skip_count}")
    _print(f"To install            : {len(to_install)}")

    if not to_install:
        _print("\n[green]All IXF NSE scripts already installed.[/green]")
        _print("Use --force to reinstall.")
        return

    _print("\nInstalling...")

    result = NseManager.install(scripts_dir=scripts_dir, force=force)

    # Summary
    _print("")
    if result["installed"]:
        _print(f"[green]Installed ({len(result['installed'])}):[/green]")
        for name in result["installed"]:
            _print(f"  [green]OK[/green]  {name}")

    if result["skipped"]:
        _print(f"[yellow]Skipped ({len(result['skipped'])}) — already installed:[/yellow]")
        for name in result["skipped"]:
            _print(f"  [dim]SKIP[/dim] {name}")

    if result["errors"]:
        _print(f"[red]Errors ({len(result['errors'])}):[/red]")
        for err in result["errors"]:
            _print(f"  [red]ERR[/red]  {err}")

    if result["success"]:
        _print(f"\n[bold green]Installation complete![/bold green]")
        _print(f"Scripts installed to: {scripts_dir}")
        _print("\nUsage examples:")
        _print("  nmap --script ics-sweep -p 20-65535 192.168.1.100")
        _print("  nmap --script ics-default-creds -p 80,8080 192.168.1.0/24")
        _print("  nmap --script ics-plc-program-access -p 102,44818,11740 192.168.1.100")
        _print("  nmap --script ics-safety-systems -p 1502,4840 192.168.1.100")
        _print("  nmap --script ics-firmware-version -p 502,44818,102 192.168.1.100")
        _print("  nmap --script ics-historian-discover -p 5450,5413,10014 192.168.1.100")
        _print("  nmap --script 'ics-*' --script-args ics-default-creds.timeout=3000 192.168.1.0/24")
    else:
        _print(f"\n[red]Installation completed with errors.[/red]")
        if any("Permission" in e for e in result["errors"]):
            _print("")
            if sys.platform == "win32":
                _print("[yellow]Tip: Run as Administrator (right-click → Run as administrator)[/yellow]")
            else:
                _print("[yellow]Tip: Run with sudo: sudo python tools/nse_install.py --install[/yellow]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nse_install",
        description="IndustrialXPL-Forge NSE Script Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tools/nse_install.py --status
  python tools/nse_install.py --list
  python tools/nse_install.py --install
  python tools/nse_install.py --install --force
  python tools/nse_install.py --install --scripts-dir /usr/share/nmap/scripts
  sudo python tools/nse_install.py --install     (Linux — may need sudo)
        """,
    )
    parser.add_argument("--install",     action="store_true", help="Install IXF NSE scripts into Nmap")
    parser.add_argument("--force",       action="store_true", help="Reinstall even if already present")
    parser.add_argument("--list",        action="store_true", help="List available IXF NSE scripts")
    parser.add_argument("--status",      action="store_true", help="Show Nmap + NSE scripts status")
    parser.add_argument("--scripts-dir", default="",          help="Custom Nmap scripts directory path")

    args = parser.parse_args()

    show_banner()

    if args.list:
        cmd_list()
    elif args.install:
        cmd_install(force=args.force, scripts_dir_override=args.scripts_dir)
    elif args.status:
        cmd_status()
    else:
        # Default: show status
        cmd_status()
        _print("\nRun with --install to install scripts.")


if __name__ == "__main__":
    main()
