"""IXF-native handlers for incorporated ics-tools (no broken vendor deps)."""

from __future__ import annotations

import csv
import json
import re
import socket
import struct
from pathlib import Path
from typing import Any, Callable

from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog

_PKG = Path(__file__).resolve().parents[2]
_VENDOR = _PKG / "resources" / "vendor"


def _bacnet_whois() -> bytes:
    return bytes([
        0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08,
    ])


def _probe_udp(host: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        return sock.recv(4096)
    except OSError:
        return b""
    finally:
        sock.close()


def _probe_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _modbus_probe(host: str, port: int = 502) -> dict[str, Any]:
    pdu = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + struct.pack(">HH", 0, 1)
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(pdu)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 8:
            return {"success": True, "detail": "Modbus/TCP response ({} bytes)".format(len(resp))}
    except OSError as exc:
        return {"success": False, "error": str(exc)}
    return {"success": False, "error": "no Modbus response"}


def _host_from_args(parsed: dict[str, str], *keys: str) -> str:
    for key in keys:
        val = parsed.get(key, "").strip()
        if val:
            return val
    pos = parsed.get("_positional", "").strip().split()
    return pos[-1] if pos else ""

def _parse_args(extra: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    args = extra or []
    i = 0
    while i < len(args):
        if args[i].startswith("-") and i + 1 < len(args):
            out[args[i]] = args[i + 1]
            i += 2
        else:
            out["_positional"] = out.get("_positional", "") + " " + args[i]
            i += 1
    return out


def _inventory_files(root: Path, pattern: str, limit: int = 30) -> list[str]:
    if not root.is_dir():
        return []
    return [str(p.relative_to(root)) for p in sorted(root.glob(pattern))[:limit]]


def handle_scadapass(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    csv_path = vendor / "scadapass.csv"
    if simulate:
        return {"simulate": True, "would_run": "native scadapass load {}".format(csv_path)}
    if not csv_path.is_file():
        return {"success": False, "error": "scadapass.csv missing"}
    rows = []
    with csv_path.open(encoding="utf-8", errors="replace") as f:
        for i, row in enumerate(csv.reader(f)):
            if i >= 30:
                break
            rows.append(row)
    return {
        "success": True,
        "mode": "native",
        "entries_preview": rows,
        "total_shown": len(rows),
        "path": str(csv_path),
    }


def handle_redpoint(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    parsed = _parse_args(extra)
    host = _host_from_args(parsed)
    port = int(parsed.get("-p", "47808"))
    nse = sorted(p.name for p in vendor.glob("*.nse"))
    if simulate:
        return {
            "simulate": True,
            "would_run": "native BACnet Who-Is {}:{} (NSE corpus: {})".format(host or "<target>", port, len(nse)),
            "nse_scripts": nse[:10],
        }
    if not host:
        return {
            "success": True,
            "mode": "native-inventory",
            "nse_scripts": nse,
            "stdout": "Redpoint NSE corpus ({} scripts). Set target: ics_tools run redpoint <ip>".format(len(nse)),
        }
    resp = _probe_udp(host, port, _bacnet_whois())
    if resp:
        return {
            "success": True,
            "mode": "native-bacnet",
            "stdout": "BACnet/IP Who-Is response from {}:{} ({} bytes)".format(host, port, len(resp)),
            "returncode": 0,
        }
    return {"success": False, "error": "No BACnet response on {}:{}".format(host, port)}


def handle_sixnet(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    parsed = _parse_args(extra)
    host = _host_from_args(parsed, "-s")
    ports = (502, 80, 23, 20547, 44818)
    if simulate:
        return {
            "simulate": True,
            "would_run": "native SIXNET probe {} ports {}".format(host or "<target>", ports),
        }
    if not host:
        return {
            "success": True,
            "mode": "native-help",
            "stdout": (
                "IXF native SIXNET tools. Usage: -s <host> or pass IP as arg.\n"
                "Probes TCP ports: {}".format(ports)
            ),
            "returncode": 0,
        }
    open_ports = [p for p in ports if _probe_tcp(host, p)]
    lines = ["SIXNET probe {} — open TCP: {}".format(host, open_ports or "none")]
    if 502 in open_ports:
        mb = _modbus_probe(host, 502)
        lines.append("Modbus: {}".format(mb.get("detail") or mb.get("error")))
    return {
        "success": True,
        "mode": "native-sixnet",
        "stdout": "\n".join(lines),
        "open_ports": open_ports,
        "returncode": 0,
    }


def handle_isf_dark_lbp(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    exploits = _inventory_files(vendor / "icssploit" / "exploits", "**/*.py", 25)
    modules = _inventory_files(vendor, "isf.py", 1)
    isf_py = vendor / "isf.py"
    if simulate:
        return {
            "simulate": True,
            "would_run": "native ISF inventory {} exploits".format(len(exploits)),
        }
    # List IXF modules that reference ISF / ICSSploit
    ixf_routes = []
    mod_root = _PKG / "modules"
    if mod_root.is_dir():
        for py in mod_root.rglob("*.py"):
            try:
                text = py.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            if "icssploit" in text.lower() or "isf" in text.lower() and "dark-lbp" in text:
                rel = py.relative_to(mod_root).with_suffix("").as_posix()
                if rel not in ixf_routes and "refs" not in rel:
                    ixf_routes.append(rel)
    ixf_routes = sorted(ixf_routes)[:20]
    return {
        "success": True,
        "mode": "native-isf",
        "stdout": (
            "ISF/ICSSploit vendor at {}\n"
            "Upstream exploits: {}\n"
            "IXF ported modules (sample): {}\n"
            "Live exploit execution: use IXF CVE/protocol modules (python2 vendor isf.py deprecated)."
        ).format(isf_py if isf_py.is_file() else vendor, len(exploits), ", ".join(ixf_routes[:8]) or "see module catalog"),
        "exploit_files": exploits[:15],
        "ixf_modules": ixf_routes,
        "returncode": 0,
    }


def handle_isf_w3h(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    parsed = _parse_args(extra)
    host = _host_from_args(parsed)
    touches = _inventory_files(vendor / "module" / "touches", "**/*.py", 20)
    if simulate:
        return {
            "simulate": True,
            "would_run": "native PLC scan (Modbus/S7) on {}".format(host or "<target>"),
            "touches": touches[:10],
        }
    if not host:
        return {
            "success": True,
            "mode": "native-inventory",
            "stdout": "ISF-W3H touches: {}\nPass target IP for Modbus probe.".format(len(touches)),
            "touches": touches,
            "returncode": 0,
        }
    results = []
    mb = _modbus_probe(host, 502)
    results.append("Modbus 502: {}".format(mb.get("detail") or mb.get("error")))
    s7_open = _probe_tcp(host, 102)
    results.append("S7comm 102: {}".format("open" if s7_open else "closed"))
    return {
        "success": any("response" in r or "open" in r for r in results),
        "mode": "native-plcscan",
        "stdout": "\n".join(results),
        "returncode": 0,
    }


def handle_attkfinder(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    py_files = _inventory_files(vendor, "*.py", 20)
    stir = vendor / "PLCcode.stir"
    offensive = vendor / "offensive.py"
    classes = []
    if offensive.is_file():
        text = offensive.read_text(encoding="utf-8", errors="replace")
        classes = re.findall(r"class\s+(\w+)", text)[:15]
    if simulate:
        return {"simulate": True, "would_run": "native ATT&CK finder inventory"}
    return {
        "success": True,
        "mode": "native-attkfinder",
        "stdout": (
            "ATT&CK Finder (IXF native inventory — neo4j/py2neo not required).\n"
            "Python modules: {}\n"
            "PLC ST sample: {}\n"
            "Offensive classes: {}\n"
            "Full graph build needs Neo4j; use IXF ICS assessment modules for live ops."
        ).format(
            ", ".join(py_files[:8]),
            "yes" if stir.is_file() else "missing",
            ", ".join(classes[:8]) or "—",
        ),
        "returncode": 0,
    }


def handle_ics_forensics(vendor: Path, extra: list[str] | None, simulate: bool) -> dict[str, Any]:
    from industrialxpl.core.ics_tools.forensics_engine import (
        inventory,
        ioc_inventory,
        match_ioc_hash,
        parse_ob_sample,
        scan_plc,
    )

    parsed = _parse_args(extra)
    host = _host_from_args(parsed, "-sc")
    ioc_hash = parsed.get("-hash", "").strip()
    if simulate:
        return {"simulate": True, "would_run": "native forensics S7/OB mapping/IOC"}
    if ioc_hash:
        return {"success": True, "mode": "native-forensics-ioc", "match": match_ioc_hash(ioc_hash)}
    if host and re.match(r"^[\d.]+$", host):
        s7 = scan_plc(host)
        ob = parse_ob_sample(host)
        return {
            "success": s7.get("success", False),
            "mode": "native-forensics-scan",
            "stdout": "S7: {}\nOB preview: {} blocks".format(
                s7.get("plc_info") or s7.get("error"),
                len(ob.get("ob_preview", [])),
            ),
            "s7": s7,
            "ob": ob,
            "returncode": 0,
        }
    inv = inventory()
    ioc = ioc_inventory()
    return {
        "success": True,
        "mode": "native-forensics",
        "stdout": (
            "ICS Forensics (IXF stdlib). Modules: {} | OB mapping: {} entries | IOC hashes: {} ({} families).\n"
            "Scan: ics_tools run ics-forensics-tools -sc <plc_ip>\n"
            "IOC:  ics_tools run ics-forensics-tools -hash <sha256>"
        ).format(
            len(inv.get("python_modules", [])),
            inv.get("ob_mapping_entries", 0),
            ioc.get("hash_count", 0),
            ioc.get("families", 0),
        ),
        "inventory": inv,
        "ioc": ioc,
        "returncode": 0,
    }


NATIVE_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "scadapass": handle_scadapass,
    "redpoint": handle_redpoint,
    "sixnet-tools": handle_sixnet,
    "isf-dark-lbp": handle_isf_dark_lbp,
    "isf-w3h": handle_isf_w3h,
    "attkfinder": handle_attkfinder,
    "ics-forensics-tools": handle_ics_forensics,
}


def run_native(
    slug: str,
    extra_args: list[str] | None = None,
    simulate: bool = False,
) -> dict[str, Any] | None:
    """Return handler result or None if slug has no native handler."""
    handler = NATIVE_HANDLERS.get(slug)
    if not handler:
        return None
    fam = IcsToolsCatalog().get(slug)
    vendor = fam.vendor_path if fam else _VENDOR / "submodules__ics-tools__{}".format(slug)
    return handler(vendor, extra_args, simulate)
