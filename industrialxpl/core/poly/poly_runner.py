"""PolyExploitRunner — Python-First multi-language exploit orchestrator.

Default mode: Python fallback (no external runtimes required).
External runtimes (ruby, node, java, gcc, go, pwsh) are OPTIONAL accelerators.
If a runtime is absent, the Python fallback implementation is used silently.

Tier system:
    Tier 0: Python stdlib (socket, struct, select) — always available
    Tier 1: pip install (pymodbus, scapy, requests, paramiko) — required
    Tier 2: pip extras (asyncua, cpppo, python-can) — optional
    Tier 3: external runtimes — optional, graceful fallback exists
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from industrialxpl.core.exploit.printer import print_info, print_warning

logger = logging.getLogger(__name__)

PROJECT_TMP = Path(__file__).resolve().parents[3] / ".tmp"
PROJECT_TMP.mkdir(parents=True, exist_ok=True)

DEFAULT_MODE = "python_fallback"

RUNTIME_HINTS: dict[str, str] = {
    "ruby":       "sudo apt install ruby  /  brew install ruby",
    "msfconsole": "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
    "node":       "https://nodejs.org/  /  sudo apt install nodejs",
    "java":       "sudo apt install default-jdk",
    "javac":      "sudo apt install default-jdk",
    "gcc":        "sudo apt install build-essential",
    "g++":        "sudo apt install build-essential",
    "go":         "https://go.dev/dl/",
    "perl":       "sudo apt install perl",
    "pwsh":       "https://github.com/PowerShell/PowerShell/releases",
    "powershell": "built-in on Windows",
}


class PolyExploitRunner:
    """Orchestrate exploits in languages other than Python.

    All methods return (returncode, stdout, stderr).
    On missing runtime: returncode=-1, stderr='runtime not found'.
    """

    def check_runtime(self, runtime: str) -> bool:
        return shutil.which(runtime) is not None

    def get_available_runtimes(self) -> dict[str, bool]:
        return {rt: self.check_runtime(rt) for rt in RUNTIME_HINTS}

    def _run(
        self,
        cmd: list,
        timeout: int = 120,
        cwd: Optional[str] = None,
    ) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or str(PROJECT_TMP),
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out after {}s".format(timeout)
        except FileNotFoundError as exc:
            return -1, "", str(exc)

    def _warn_fallback(self, runtime: str) -> None:
        hint = RUNTIME_HINTS.get(runtime, "install {}".format(runtime))
        print_warning(
            "[poly] '{}' not found — using Python fallback. "
            "To use the native runtime: {}".format(runtime, hint)
        )

    def run_with_fallback(
        self,
        runtime: str,
        external_cmd: list,
        python_fallback: Callable,
        *args,
        **kwargs,
    ) -> tuple[int, str, str]:
        """Run external command if available, else call python_fallback."""
        if self.check_runtime(runtime):
            return self._run(external_cmd)
        self._warn_fallback(runtime)
        try:
            python_fallback(*args, **kwargs)
            return 0, "Python fallback executed.", ""
        except Exception as exc:
            return -1, "", "Python fallback failed: {}".format(exc)

    def run_ruby(self, script_path: str, args: list) -> tuple[int, str, str]:
        if not self.check_runtime("ruby"):
            self._warn_fallback("ruby")
            return -1, "", "ruby not found — Python fallback required"
        return self._run(["ruby", script_path] + args)

    def run_msf_module(
        self,
        module_path: str,
        options: dict,
    ) -> tuple[int, str, str]:
        """Execute a Metasploit module via msfconsole resource script.

        Note: Metasploit is NOT installed on this machine.
        Python fallback implementations are the primary path.
        """
        if not self.check_runtime("msfconsole"):
            self._warn_fallback("msfconsole")
            return -1, "", "msfconsole not found — use Python fallback implementation"

        rc_lines = ["use {}".format(module_path)]
        for k, v in options.items():
            rc_lines.append("set {} {}".format(k, v))
        rc_lines.extend(["exploit -j", "sleep 10", "exit"])
        rc_content = "\n".join(rc_lines)

        rc_file = PROJECT_TMP / "ixf_msf.rc"
        rc_file.write_text(rc_content, encoding="utf-8")
        return self._run(["msfconsole", "-q", "-r", str(rc_file)], timeout=90)

    def compile_and_run_c(self, source_path: str, args: list) -> tuple[int, str, str]:
        if not self.check_runtime("gcc"):
            self._warn_fallback("gcc")
            return -1, "", "gcc not found — Python fallback required"
        bin_path = PROJECT_TMP / Path(source_path).stem
        ret, out, err = self._run(["gcc", source_path, "-o", str(bin_path), "-lpthread"])
        if ret != 0:
            return ret, out, err
        return self._run([str(bin_path)] + args)

    def compile_and_run_cpp(self, source_path: str, args: list) -> tuple[int, str, str]:
        if not self.check_runtime("g++"):
            self._warn_fallback("g++")
            return -1, "", "g++ not found — Python fallback required"
        bin_path = PROJECT_TMP / Path(source_path).stem
        ret, out, err = self._run(["g++", source_path, "-o", str(bin_path), "-lstdc++"])
        if ret != 0:
            return ret, out, err
        return self._run([str(bin_path)] + args)

    def run_java(self, jar_or_source: str, args: list) -> tuple[int, str, str]:
        if not self.check_runtime("java"):
            self._warn_fallback("java")
            return -1, "", "java not found — Python fallback required"
        if jar_or_source.endswith(".java"):
            if not self.check_runtime("javac"):
                return -1, "", "javac not found"
            ret, out, err = self._run(["javac", jar_or_source, "-d", str(PROJECT_TMP)])
            if ret != 0:
                return ret, out, err
            class_name = Path(jar_or_source).stem
            return self._run(["java", "-cp", str(PROJECT_TMP), class_name] + args)
        return self._run(["java", "-jar", jar_or_source] + args)

    def run_node(self, script_path: str, args: list) -> tuple[int, str, str]:
        if script_path.endswith(".ts"):
            if self.check_runtime("ts-node"):
                return self._run(["ts-node", script_path] + args)
            if self.check_runtime("npx"):
                return self._run(["npx", "tsx", script_path] + args)
            self._warn_fallback("node")
            return -1, "", "ts-node/npx not found"
        if not self.check_runtime("node"):
            self._warn_fallback("node")
            return -1, "", "node not found — Python fallback required"
        return self._run(["node", script_path] + args)

    def run_go(self, source_path: str, args: list) -> tuple[int, str, str]:
        if not self.check_runtime("go"):
            self._warn_fallback("go")
            return -1, "", "go not found — Python fallback required"
        return self._run(["go", "run", source_path] + args)

    def run_powershell(self, script_path: str, args: list) -> tuple[int, str, str]:
        runtime = "pwsh" if self.check_runtime("pwsh") else "powershell"
        if not self.check_runtime(runtime):
            self._warn_fallback("pwsh")
            return -1, "", "pwsh/powershell not found"
        return self._run(
            [runtime, "-ExecutionPolicy", "Bypass", "-File", script_path] + args
        )

    def env_report(self) -> None:
        """Print Tier 3 runtime availability table."""
        from industrialxpl.core.exploit.printer import print_table
        rows = []
        for rt, hint in RUNTIME_HINTS.items():
            status = "OK" if self.check_runtime(rt) else "OPTIONAL (not installed)"
            rows.append((rt, status, hint[:60]))
        print_table(
            ["Runtime", "Status", "Install Hint"],
            rows,
            title="Tier 3 External Runtimes (all optional — Python fallback available)",
        )
