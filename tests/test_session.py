"""Tests for industrialxpl.core.session persistence module."""


import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.core.session import HostSession, ModuleResult, host_id


def test_host_id_deterministic():
    h1 = host_id("10.0.0.1", "AA:BB:CC:DD:EE:FF")
    h2 = host_id("10.0.0.1", "AA:BB:CC:DD:EE:FF")
    assert h1 == h2
    assert len(h1) == 16


def test_host_id_different():
    h1 = host_id("10.0.0.1")
    h2 = host_id("10.0.0.2")
    assert h1 != h2


def test_host_id_case_insensitive():
    h1 = host_id("10.0.0.1", "aa:bb:cc:dd:ee:ff")
    h2 = host_id("10.0.0.1", "AA:BB:CC:DD:EE:FF")
    assert h1 == h2


def test_module_result_to_dict():
    r = ModuleResult(
        module_path="ics.modbus.write_coil",
        vulnerable=True,
        elapsed_s=0.5,
        port=502,
        protocol="modbus",
    )
    d = r.to_dict()
    assert d["module_path"] == "ics.modbus.write_coil"
    assert d["vulnerable"] is True
    assert d["port"] == 502


def test_module_result_from_dict():
    d = {
        "module_path": "ics.s7.read_szl",
        "vulnerable": False,
        "elapsed_s": 1.0,
        "port": 102,
        "protocol": "s7comm",
    }
    r = ModuleResult.from_dict(d)
    assert r.module_path == "ics.s7.read_szl"
    assert r.vulnerable is False


def test_module_result_roundtrip():
    r = ModuleResult(module_path="test.mod", vulnerable=True, elapsed_s=2.0)
    r2 = ModuleResult.from_dict(r.to_dict())
    assert r2.module_path == r.module_path
    assert r2.vulnerable == r.vulnerable


def test_host_session_defaults():
    s = HostSession(host_id="abc123", ip="192.168.1.100")
    assert s.open_ports == []
    assert s.module_results == []


def test_host_session_add_result():
    s = HostSession(host_id="test", ip="10.0.0.1")
    r = ModuleResult(module_path="ics.rce", vulnerable=True)
    s.add_result(r)
    assert len(s.module_results) == 1
    assert "ics.rce" in s.vulns_found


def test_host_session_modules_pending():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.matched_modules = ["mod.a", "mod.b", "mod.c"]
    s.module_results = [ModuleResult(module_path="mod.a")]
    pending = s.modules_pending()
    assert "mod.b" in pending
    assert "mod.a" not in pending


def test_host_session_merge_discovery():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.open_ports = [502]
    s.merge_discovery(ip="10.0.0.1", open_ports=[502, 102, 44818])
    assert 502 in s.open_ports
    assert 102 in s.open_ports
    assert 44818 in s.open_ports
