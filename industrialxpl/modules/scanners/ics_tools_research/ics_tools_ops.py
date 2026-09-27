"""Unified ICS-tools ops — analyze, run, compile vendor tools from IXF."""

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
    DestructiveGate,
)
from industrialxpl.core.ics_tools import IcsToolsCatalog, IcsToolsOrchestrator


class Exploit(Exploit):
    __info__ = {
        "name": "ICS-Tools Native Ops",
        "description": (
            "List, analyze, run, and compile incorporated ics-tools vendor trees "
            "(SCADAPASS, Redpoint NSE, SIXNET, ISF/ICSSploit, ATT&CK Finder, forensics). "
            "Authorized lab targets only."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": ("IXF ics-tools incorporation",),
        "devices": ("ICS lab", "OT assessment"),
        "impact": "READ",
        "mitre_techniques": ["T1588", "T1592"],
        "severity": "INFO",
    }

    tool = OptString("", "ics-tools slug (attkfinder, redpoint, scadapass, sixnet-tools, ...)")
    list_all = OptBool(False, "List all incorporated ics-tools")
    action = OptString("analyze", "analyze | run | plan | compile")
    extra_args = OptString("", "Extra CLI args for vendor entry (space-separated)")
    target = OptIP("", "Lab target IP (for NSE / sixnet)")
    port = OptPort(47808, "Target port (BACnet default 47808)")
    simulate = OptBool(True, "Simulate — do not invoke vendor binaries")
    destructive = OptBool(False, "Live vendor execution against target")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        orch = IcsToolsOrchestrator()
        action = (self.action or "analyze").lower()

        if self.list_all or not self.tool:
            rows = []
            for slug in orch.list_tools():
                fam = IcsToolsCatalog().get(slug)
                rows.append((slug, fam.label if fam else slug, fam.entry_script if fam else ""))
            print_table(["Slug", "Label", "Entry"], rows, title="ICS-Tools ({})".format(len(rows)))
            return

        slug = self.tool.strip()
        extra = [a for a in str(self.extra_args).split() if a]

        if action == "plan":
            plan = orch.build_plan(slug, target=self.target or "")
            if plan.get("error"):
                print_error(plan["error"])
                return
            print_table(
                ["Phase", "Action", "Detail"],
                [(s["phase"], s["action"], s["detail"][:60]) for s in plan.get("plan_steps", [])],
                title="Plan: {}".format(plan.get("label", slug)),
            )
            return

        if action == "analyze":
            info = orch.analyze(slug)
            if info.get("error"):
                print_error(info["error"])
                return
            print_success("{} — {}".format(info["label"], info["interpreter"]))
            print_info("Vendor: {}".format(info["vendor_path"]))
            print_info("Entry: {}".format(info["entry"]))
            if info.get("nse_scripts"):
                print_info("NSE: {}".format(", ".join(info["nse_scripts"][:8])))
            return

        if action == "compile":
            r = orch.runner.compile_vendor(slug, simulate=self.simulate)
            if r.get("simulate"):
                print_warning("[SIMULATE] compile: {}".format(r.get("solutions", r)))
            elif r.get("success"):
                print_success(r.get("note", "compile ok"))
            else:
                print_error(r.get("error", "compile failed"))
            return

        if action == "run":
            if slug == "redpoint" and self.target and not self.simulate:
                extra = ["-p", str(self.port), "--script", "BACnet-discover-enumerate", self.target]
            if slug == "sixnet-tools" and self.target:
                extra = (extra or []) + ["-s", self.target]

            live = not self.simulate and self.destructive
            if live and self.target:
                if not DestructiveGate.require_confirmation(
                    "ics_tools_ops",
                    self.target,
                    "HIGH",
                    "Run vendor ics-tool {} against {}".format(slug, self.target),
                ):
                    return

            r = orch.run(slug, args=extra, simulate=not live and self.simulate)
            if r.get("simulate"):
                print_warning("[SIMULATE] {}".format(r.get("would_run")))
            elif r.get("success"):
                if r.get("stdout"):
                    print_info(r["stdout"][:1500])
                print_success("Vendor run finished (rc={})".format(r.get("returncode", 0)))
            else:
                print_error(r.get("error", r.get("stderr", "failed")[:200]))
            return

        print_error("Unknown action: {} (analyze|run|plan|compile)".format(action))
