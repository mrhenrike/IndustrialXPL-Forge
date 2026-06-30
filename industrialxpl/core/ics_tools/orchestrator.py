"""ICS-tools orchestration for IXF."""

from __future__ import annotations

from typing import Any

from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
from industrialxpl.core.ics_tools.runner import IcsToolsRunner


class IcsToolsOrchestrator:
    def __init__(self) -> None:
        self.catalog = IcsToolsCatalog()
        self.runner = IcsToolsRunner()

    def list_tools(self) -> list[str]:
        return self.catalog.list_slugs()

    def analyze(self, slug: str) -> dict[str, Any]:
        return self.runner.analyze(slug)

    def build_plan(self, slug: str, target: str = "") -> dict[str, Any]:
        info = self.analyze(slug)
        if info.get("error"):
            return info
        steps = [
            {"phase": 1, "action": "inventory", "detail": info["vendor_path"]},
            {"phase": 2, "action": "entry", "detail": "{} via {}".format(info["entry"], info["interpreter"])},
            {"phase": 3, "action": "ixf_module", "detail": "use {}".format(info["ixf_module"])},
        ]
        if target:
            steps.append({"phase": 4, "action": "lab_target", "detail": target})
        return {**info, "plan_steps": steps}

    def run(self, slug: str, args: list[str] | None = None, simulate: bool = True) -> dict[str, Any]:
        return self.runner.run_entry(slug, extra_args=args, simulate=simulate)
