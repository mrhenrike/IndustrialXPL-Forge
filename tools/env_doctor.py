#!/usr/bin/env python3
"""IndustrialXPL-Forge environment health checker.

Verifies Python version, required pip packages (Tier 1-2),
and optional external runtimes (Tier 3 — all optional, Python fallback available).

Usage: python tools/env_doctor.py
"""

import importlib
import platform
import shutil
import sys


def _check(label: str, ok: bool, note: str = "") -> tuple[str, str]:
    status = "\033[32mOK\033[0m" if ok else "\033[31mMISSING\033[0m"
    return (label, status, note)


def _check_import(pkg: str, import_name: str = None) -> bool:
    try:
        importlib.import_module(import_name or pkg)
        return True
    except ImportError:
        return False


def _check_version(pkg: str, import_name: str = None) -> str:
    try:
        mod = importlib.import_module(import_name or pkg)
        return getattr(mod, "__version__", "installed")
    except ImportError:
        return "not found"


def main() -> None:
    print("\n" + "=" * 68)
    print("  IndustrialXPL-Forge (IXF) — Environment Health Check")
    print("=" * 68)

    rows: list[tuple[str, str, str]] = []

    # ── Python version ───────────────────────────────────────────────────
    print("\n[Python]")
    pv = sys.version_info
    py_ok = pv >= (3, 9)
    v_str = "{}.{}.{}".format(pv.major, pv.minor, pv.micro)
    status = "\033[32mOK\033[0m" if py_ok else "\033[31mFAIL (requires 3.9+)\033[0m"
    print("  Python {:>10}  {}  ({})".format(v_str, status, platform.python_implementation()))

    # ── Tier 1 — required pip packages ──────────────────────────────────
    print("\n[Tier 1 — Required pip dependencies]")
    tier1 = [
        ("requests",  "requests",  "pip install requests"),
        ("paramiko",  "paramiko",  "pip install paramiko"),
        ("scapy",     "scapy",     "pip install scapy"),
        ("rich",      "rich",      "pip install rich"),
        ("psutil",    "psutil",    "pip install psutil"),
        ("pysnmp",    "pysnmp",    "pip install pysnmp"),
    ]
    for pkg, imp, install in tier1:
        ok = _check_import(pkg, imp)
        ver = _check_version(pkg, imp)
        status = "\033[32mOK ({:>12})\033[0m".format(ver) if ok else "\033[31mMISSING\033[0m"
        note = "" if ok else install
        print("  {:<15} {}  {}".format(pkg, status, note))

    # ── Tier 2 — optional pip packages ──────────────────────────────────
    print("\n[Tier 2 — Optional pip extras (needed for specific protocols)]")
    tier2 = [
        ("pymodbus",   "pymodbus",  "pip install pymodbus>=3.5  (Modbus TCP/RTU)"),
        ("asyncua",    "asyncua",   "pip install asyncua          (OPC UA)"),
        ("cpppo",      "cpppo",     "pip install cpppo            (EtherNet/IP)"),
        ("python-can", "can",       "pip install python-can       (CAN/CANopen)"),
    ]
    for pkg, imp, install in tier2:
        ok = _check_import(pkg, imp)
        ver = _check_version(pkg, imp)
        status = "\033[32mOK ({:>12})\033[0m".format(ver) if ok else "\033[33mOPTIONAL\033[0m"
        note = "" if ok else install
        print("  {:<15} {}  {}".format(pkg, status, note))

    # ── Tier 3 — external runtimes (all optional) ────────────────────────
    print("\n[Tier 3 — External runtimes (ALL OPTIONAL — Python fallback always available)]")
    tier3 = [
        ("ruby",       "For Metasploit Ruby modules (not installed here — Python native used)"),
        ("msfconsole", "Metasploit Framework (optional, not installed — Python fallback)"),
        ("node",       "Node.js — for JavaScript/TypeScript exploits"),
        ("java",       "Java — for Java deserialization exploits"),
        ("javac",      "Java compiler — needed to compile .java sources"),
        ("gcc",        "GCC C compiler — for C-based native exploits"),
        ("g++",        "G++ C++ compiler — for C++ native exploits"),
        ("go",         "Go runtime — for FrostyGoop and Go-based tools"),
        ("perl",       "Perl — for legacy ICS scripts"),
        ("pwsh",       "PowerShell — for Windows EWS exploitation"),
    ]
    for runtime, desc in tier3:
        found = shutil.which(runtime) is not None
        status = "\033[32mOK\033[0m" if found else "\033[33mOPTIONAL (not installed)\033[0m"
        print("  {:<13} {}  {}".format(runtime, status, desc[:55] if not found else ""))

    # ── IXF modules ─────────────────────────────────────────────────────
    print("\n[IXF Module Index]")
    try:
        from industrialxpl.core.exploit.utils import index_modules
        mods = index_modules()
        print("  Modules indexed: \033[32m{}\033[0m".format(len(mods)))
    except Exception as exc:
        print("  Module indexing failed: \033[31m{}\033[0m".format(exc))

    print("\n[Summary]")
    print("  Python-First mode: all IXF features work without Tier 3 runtimes.")
    print("  Install Tier 2: pip install industrialxpl[ot]")
    print("  Install all:    pip install industrialxpl[full]")
    print()


if __name__ == "__main__":
    main()
