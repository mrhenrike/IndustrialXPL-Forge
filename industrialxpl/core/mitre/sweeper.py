"""MitreTacticSweeper — executes IXF modules by MITRE ATT&CK for ICS tactic or technique."""

import ipaddress
import time
from typing import Optional

from industrialxpl.core.exploit.printer import print_error, print_info, print_status, print_success, print_table
from industrialxpl.core.exploit.utils import import_exploit, humanize_path
from industrialxpl.core.exploit.exceptions import IXFException
from industrialxpl.core.mitre.tactics import TACTIC_ALIASES, TACTICS, TACTIC_TIDS
from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, TACTIC_INDEX, build_index


class MitreTacticSweeper:
    """Execute all IXF modules mapped to a MITRE ATT&CK for ICS tactic or technique.

    Args:
        target:           Target IP address or CIDR.
        port:             Optional port override (0 = use module default).
        simulate:         If True, print payloads without sending.
        destructive:      If True, enable real write/destructive execution.
        rate_limit_ms:    Milliseconds between modules (default 500ms — OT safe).
        stop_on_first_vuln: Stop after first VULNERABLE result.
        check_only:       If True, only run check() — never run().
        module_paths:     Pre-built module list (passed from interpreter).
    """

    def __init__(
        self,
        target: str = "",
        port: int = 0,
        simulate: bool = False,
        destructive: bool = False,
        rate_limit_ms: int = 500,
        stop_on_first_vuln: bool = False,
        check_only: bool = False,
        module_paths: list | None = None,
    ) -> None:
        self.target = target
        self.port = port
        self.simulate = simulate
        self.destructive = destructive
        self.rate_limit_ms = rate_limit_ms
        self.stop_on_first_vuln = stop_on_first_vuln
        self.check_only = check_only
        self.results: list[dict] = []
        build_index(module_paths)

    def sweep_tactic(self, tactic: str) -> list[dict]:
        """Execute all modules for a tactic name or TA-ID."""
        tactic_id = TACTIC_ALIASES.get(tactic.lower(), tactic.upper())
        tactic_name = TACTICS.get(tactic_id, tactic)
        modules = TACTIC_INDEX.get(tactic_id, [])
        mode = "simulate" if self.simulate else "LIVE"
        print_status(
            f"[mitre-sweep] Tactic: {tactic_name} ({tactic_id}) — {len(modules)} modules [{mode}]"
        )
        if not modules:
            print_error(f"No IXF modules found for tactic {tactic_id}.")
            return []
        return self._run_modules(modules, context=f"tactic:{tactic_id}")

    def sweep_technique(self, tid: str) -> list[dict]:
        """Execute all modules for a technique ID (e.g. T0843 or T0843.001)."""
        tid = tid.upper()
        modules = TECHNIQUE_INDEX.get(tid, [])
        mode = "simulate" if self.simulate else "LIVE"
        print_status(
            f"[ttp] Technique: {tid} — {len(modules)} modules [{mode}] — Target: {self.target}"
        )
        if not modules:
            print_error(f"No IXF modules for {tid}. Use 'ttp-list' to see all TTP-IDs.")
            return []
        return self._run_modules(modules, context=f"technique:{tid}")

    def sweep_all(self) -> list[dict]:
        """Execute ALL IXF modules with MITRE mapping."""
        all_mods = list({m for mods in TECHNIQUE_INDEX.values() for m in mods})
        print_status(
            f"[mitre-all] Full sweep — {len(all_mods)} unique modules [simulate={self.simulate}]"
        )
        return self._run_modules(all_mods, context="all")

    def sweep_cidr(self, cidr: str, tactic: str) -> dict[str, list[dict]]:
        """Discover live OT hosts in CIDR then sweep each with the given tactic."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            print_error(f"Invalid CIDR: {cidr}")
            return {}

        print_status(f"[cidr-sweep] Scanning {cidr}…")
        live_hosts = self._discover_hosts(network)
        print_success(f"[cidr-sweep] {len(live_hosts)} host(s) responding.")

        all_results: dict[str, list[dict]] = {}
        for host in live_hosts:
            self.target = host
            all_results[host] = self.sweep_tactic(tactic)
        return all_results

    # ── Private ────────────────────────────────────────────────────────────

    def _run_modules(self, module_paths: list, context: str) -> list[dict]:
        seen: set = set()
        for i, path in enumerate(module_paths, 1):
            if path in seen:
                continue
            seen.add(path)

            result: dict = {
                "module": path,
                "target": self.target,
                "context": context,
                "status": "NOT_RUN",
                "mitre_techniques": [],
                "error": None,
            }

            print_status(f"[{i}/{len(module_paths)}] {humanize_path(path)}")

            try:
                cls = import_exploit(f"industrialxpl.modules.{path}")
                mod = cls()

                if hasattr(mod, "target") and self.target:
                    mod.target = self.target
                if self.port and hasattr(mod, "port"):
                    mod.port = self.port
                mod.simulate = self.simulate
                mod.destructive = self.destructive
                mod._simulate_mode = self.simulate

                info = mod.get_info()
                result["mitre_techniques"] = info.get("mitre_techniques", [])

                # check()
                is_vuln = False
                try:
                    is_vuln = bool(mod.check())
                    result["status"] = "VULNERABLE" if is_vuln else "NOT_VULNERABLE"
                except NotImplementedError:
                    result["status"] = "NOT_IMPLEMENTED"
                except Exception as exc:
                    result["status"] = "CHECK_ERROR"
                    result["error"] = str(exc)[:120]

                # run() — only if not check_only
                if not self.check_only and (self.simulate or is_vuln):
                    try:
                        mod.run()
                    except NotImplementedError:
                        pass
                    except Exception as exc:
                        result["error"] = str(exc)[:120]

                if self.simulate and result["status"] in ("VULNERABLE", "NOT_VULNERABLE"):
                    result["status"] = "SIMULATED ({})".format(result["status"])

                if self.stop_on_first_vuln and is_vuln:
                    print_success(f"[sweep] First VULNERABLE found: {path} — stopping.")
                    self.results.append(result)
                    break

            except IXFException as exc:
                result["status"] = "LOAD_ERROR"
                result["error"] = str(exc)[:120]
                print_error(f"[sweep] {path}: {exc}")
            except Exception as exc:
                result["status"] = "ERROR"
                result["error"] = str(exc)[:120]

            self.results.append(result)
            time.sleep(self.rate_limit_ms / 1000.0)

        self._print_summary()
        return self.results

    def _print_summary(self) -> None:
        rows = [
            (
                humanize_path(r["module"])[-50:],
                r["status"],
                ", ".join(r.get("mitre_techniques", [])[:2]),
            )
            for r in self.results
        ]
        print_table(
            ["Module", "Status", "MITRE Techniques"],
            rows,
            title=f"MITRE Sweep — Target: {self.target}",
        )
        vuln = sum(1 for r in self.results if "VULNERABLE" in r["status"])
        print_success(f"{vuln}/{len(self.results)} modules: VULNERABLE/POSSIBLY_VULNERABLE")

    def _discover_hosts(self, network: ipaddress.IPv4Network) -> list[str]:
        """Quick Modbus port-502 probe to find live OT hosts."""
        import socket
        live = []
        for host in list(network.hosts())[:254]:
            try:
                s = socket.socket()
                s.settimeout(0.3)
                s.connect((str(host), 502))
                s.close()
                live.append(str(host))
            except Exception:
                pass
        return live
