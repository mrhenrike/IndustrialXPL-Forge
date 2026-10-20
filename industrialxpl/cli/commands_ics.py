"""ICS-tools vendor integration and NSE script management commands (mixin)."""


from typing import TYPE_CHECKING

from industrialxpl.core.exploit.printer import (
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
)

if TYPE_CHECKING:
    pass


class ICSCommandsMixin:
    """ICS-tools and NSE commands extracted from IXFInterpreter."""

    def command_ics_tools(self, args: str, **kwargs) -> None:
        """ICS-tools vendor analyze, run, compile."""
        parts = args.strip().split()
        sub = (parts[0].lower() if parts else "help")

        from industrialxpl.core.ics_tools import IcsToolsCatalog, IcsToolsOrchestrator

        if sub in ("help", "?", ""):
            print_info("""
ICS-tools commands (incorporated vendor integration):

  ics_tools list                 List tools (SCADAPASS, Redpoint, SIXNET, ISF, ...)
  ics_tools matrix               Native vs vendor entry matrix
  ics_tools analyze <slug>       Vendor inventory + entry script
  ics_tools plan <slug>          Orchestration plan
  ics_tools run <slug> [args...] Run vendor entry (add setg TARGET for NSE/sixnet)
  ics_tools compile <slug>       Compile native/.sln where applicable

  use scanners/ics_tools_research/ics_tools_ops

Examples:
  ics_tools list
  ics_tools analyze scadapass
  setg TARGET 192.168.1.10
  ics_tools run redpoint
""")
            return

        orch = IcsToolsOrchestrator()

        if sub == "list":
            rows = [(s, IcsToolsCatalog().get(s).label) for s in orch.list_tools()]
            print_table(["Slug", "Label"], rows, title="ICS-Tools")
            return

        if sub == "matrix":
            rows = []
            for slug in orch.list_tools():
                fam = IcsToolsCatalog().get(slug)
                rows.append((slug, fam.interpreter if fam else "", fam.entry_script if fam else "", "IXF native"))
            print_table(["Slug", "Interp", "Entry", "Runtime"], rows, title="ICS-Tools Matrix")
            return

        if sub == "analyze" and len(parts) >= 2:
            info = orch.analyze(parts[1])
            if info.get("error"):
                print_error(info["error"])
                return
            print_success("{} [{}] entry={}".format(info["label"], info["interpreter"], info["entry"]))
            print_info("Path: {}".format(info["vendor_path"]))
            return

        if sub == "plan" and len(parts) >= 2:
            plan = orch.build_plan(parts[1], target=str(self.global_variables.get("TARGET", "")))
            if plan.get("error"):
                print_error(plan["error"])
                return
            print_table(
                ["Phase", "Action", "Detail"],
                [(s["phase"], s["action"], s["detail"][:55]) for s in plan.get("plan_steps", [])],
                title="Plan",
            )
            return

        if sub == "run" and len(parts) >= 2:
            slug = parts[1]
            extra = parts[2:]
            target = str(self.global_variables.get("TARGET", ""))
            if slug == "redpoint" and target:
                extra = ["-p", "47808", "--script", "BACnet-discover-enumerate", target]
            r = orch.run(slug, args=extra, simulate=False)
            if r.get("stdout"):
                print_info(r["stdout"][:2000])
            if r.get("success"):
                print_success("run ok")
            else:
                print_error(r.get("error", r.get("stderr", "")[:200]))
            return

        if sub == "compile" and len(parts) >= 2:
            r = orch.runner.compile_vendor(parts[1], simulate=False)
            print_success(str(r)) if r.get("success") else print_error(r.get("error", "failed"))
            return

        print_error(f"Unknown: {sub}")
        self.command_ics_tools("help")

    def command_assess(self, args: str, **kwargs) -> None:
        module_path = args.strip()
        if not module_path:
            print_error("Usage: assess <module_path>")
            return
        path = module_path if module_path.startswith("assessment") else f"assessment/{module_path}"
        self.command_use(path)
        if self.current_module:
            self.command_run("")

    # -- NSE (Nmap Scripting Engine) commands ---------------------------------

    def command_nse(self, args: str = "", **kwargs) -> None:
        """Manage IXF Nmap NSE scripts. Usage: nse [install|list|status] [--force]"""
        from industrialxpl.core.nse.nse_manager import NSE_SCRIPTS_DIR, NseManager

        parts = args.strip().split()
        subcmd = parts[0].lower() if parts else "status"
        force = "--force" in parts

        if subcmd in ("status", ""):
            NseManager.status_report()
            nmap_bin = NseManager.find_nmap()
            if not nmap_bin:
                print_warning(
                    "Nmap not installed. Install it first:\n"
                    "  Linux:   sudo apt install nmap\n"
                    "  macOS:   brew install nmap\n"
                    "  Windows: https://nmap.org/download\n"
                    f"IXF NSE scripts are at: {NSE_SCRIPTS_DIR}\n"
                    "After installing Nmap, run: nse install"
                )
            else:
                scripts_dir = NseManager.find_scripts_dir()
                if scripts_dir:
                    not_installed = [
                        s.name for s in NseManager.list_ixf_scripts()
                        if not (scripts_dir / s.name).exists()
                    ]
                    if not_installed:
                        print_info(f"Run 'nse install' to install {len(not_installed)} script(s).")

        elif subcmd == "list":
            scripts = NseManager.list_ixf_scripts()
            scripts_dir = NseManager.find_scripts_dir()
            rows = []
            for s in scripts:
                status = "installed" if (scripts_dir and (scripts_dir / s.name).exists()) else "not installed"
                rows.append((s.name, status, f"{s.stat().st_size:,} B"))
            if rows:
                print_table(
                    ["Script", "Status", "Size"],
                    rows,
                    title=f"IXF NSE Scripts ({len(scripts)} total) : {NSE_SCRIPTS_DIR}",
                )
            else:
                print_error("No IXF NSE scripts found.")

        elif subcmd == "install":
            nmap_bin = NseManager.find_nmap()
            if not nmap_bin:
                print_error("Nmap is NOT installed on this system.")
                print_warning(
                    "Install Nmap first:\n"
                    "  Linux:   sudo apt install nmap\n"
                    "  macOS:   brew install nmap\n"
                    "  Windows: https://nmap.org/download\n"
                    f"\nIXF NSE scripts stored at: {NSE_SCRIPTS_DIR}\n"
                    "Copy .nse files manually to your Nmap scripts dir,\n"
                    "then run: nmap --script-updatedb"
                )
                return

            scripts_dir = NseManager.find_scripts_dir()
            if not scripts_dir:
                print_error("Nmap scripts directory not found.")
                print_info("Provide manually: python tools/nse_install.py --install --scripts-dir /path")
                return

            print_status(f"[NSE] Installing to: {scripts_dir}")
            result = NseManager.install(scripts_dir=scripts_dir, force=force)

            if result["installed"]:
                for name in result["installed"]:
                    print_success(f"  Installed: {name}")
            if result["skipped"]:
                print_info("  Skipped (already installed): {} : use 'nse install --force'".format(
                    len(result['skipped'])))
            if result["errors"]:
                for err in result["errors"]:
                    print_error(f"  {err}")
                if any("Permission" in e for e in result["errors"]):
                    import sys as _sys
                    if _sys.platform == "win32":
                        print_warning("Run IXF as Administrator to install into Program Files.")
                    else:
                        print_warning("Run: sudo python tools/nse_install.py --install")

            if result["success"] and result["installed"]:
                print_success("\nInstalled {} IXF NSE script(s) to {}".format(
                    len(result['installed']), scripts_dir))
                print_info("Usage: nmap --script ics-sweep -p 20-65535 <target>")
                print_info("       nmap --script 'ics-*' <target>")
                print_info("       nmap --script ics-default-creds -p 80,8080 <target>")
            elif not result["installed"] and not result["errors"]:
                print_info("All IXF NSE scripts already installed.")

        else:
            print_error(f"Unknown nse subcommand: '{subcmd}'")
            print_info("Usage: nse [install|list|status] [--force]")
