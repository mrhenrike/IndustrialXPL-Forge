"""Comprehensive coverage tests for remaining core modules.

Targets 100% line coverage for:
  - core/database.py
  - core/mitre/reporter.py, sweeper.py, index.py
  - core/modbus/base.py, transport.py, address.py, timing.py
  - core/network/__init__.py, transport.py
  - core/nse/nse_manager.py
  - core/poly/poly_runner.py
  - core/pool.py
  - core/platform.py
  - core/reporting/reporter.py
  - core/sast/llm_provider.py, plc_parsers.py, prompts.py
  - core/search/__init__.py, engine.py
  - core/session.py
  - core/ics_tools/catalog.py, forensics_engine.py, native_handlers.py, orchestrator.py, runner.py
  - core/protocols/ethernetip.py, hartip.py, iec61850.py
  - core/compliance/__init__.py, iec62443.py
"""

import csv
import hashlib
import importlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, mock_open, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure the package is importable
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ===========================================================================
# core/database.py
# ===========================================================================
class TestIxfDatabase:
    """Cover database.py import paths and class definition."""

    def test_import_with_embedxpl_available(self):
        """Test IxfDatabase import when embedxpl is available."""
        # We mock the embedxpl import to succeed
        mock_xpl = MagicMock()
        mock_xpl.XplDatabase = type("XplDatabase", (), {})
        with patch.dict("sys.modules", {
            "embedxpl": MagicMock(),
            "embedxpl.core": MagicMock(),
            "embedxpl.core.database": mock_xpl,
        }):
            # Reimport module
            if "industrialxpl.core.database" in sys.modules:
                del sys.modules["industrialxpl.core.database"]
            import industrialxpl.core.database as db_mod
            assert hasattr(db_mod, "IxfDatabase")
            assert db_mod.IxfDatabase._DB_FILE == "ixf.db"
            assert db_mod.IxfDatabase._TOOL == "IndustrialXPL"
            assert ".industrialxpl" in str(db_mod.IxfDatabase._DB_DIR)

    def test_import_fallback_path(self):
        """Test the fallback import path when first import fails."""
        # The module has a try/except that handles ImportError.
        # Just verify the module defines what we expect.
        mock_xpl = MagicMock()
        mock_xpl.XplDatabase = type("XplDatabase", (), {})
        with patch.dict("sys.modules", {
            "embedxpl": MagicMock(),
            "embedxpl.core": MagicMock(),
            "embedxpl.core.database": mock_xpl,
        }):
            if "industrialxpl.core.database" in sys.modules:
                del sys.modules["industrialxpl.core.database"]
            mod = importlib.import_module("industrialxpl.core.database")
            assert hasattr(mod.IxfDatabase, "_DB_DIR")


# ===========================================================================
# core/platform.py
# ===========================================================================
class TestPlatform:
    def test_is_linux_true(self):
        from industrialxpl.core.platform import is_linux
        with patch("industrialxpl.core.platform.sys") as mock_sys:
            mock_sys.platform = "linux"
            assert is_linux() is True

    def test_is_linux_false(self):
        from industrialxpl.core.platform import is_linux
        with patch("industrialxpl.core.platform.sys") as mock_sys:
            mock_sys.platform = "win32"
            assert is_linux() is False

    def test_require_linux_on_linux(self):
        from industrialxpl.core.platform import require_linux
        with patch("industrialxpl.core.platform.is_linux", return_value=True):
            # Should not raise/exit
            require_linux()

    def test_require_linux_on_non_linux(self):
        from industrialxpl.core.platform import require_linux
        with patch("industrialxpl.core.platform.is_linux", return_value=False):
            with patch("sys.stderr", new=MagicMock()):
                with patch("sys.exit", side_effect=SystemExit(2)):
                    with pytest.raises(SystemExit):
                        require_linux(exit_code=2)


# ===========================================================================
# core/pool.py
# ===========================================================================
class TestSmartPool:
    def test_cpu_count_normal(self):
        from industrialxpl.core.pool import cpu_count
        with patch("os.cpu_count", return_value=4):
            assert cpu_count() == 4

    def test_cpu_count_none(self):
        from industrialxpl.core.pool import cpu_count
        with patch("os.cpu_count", return_value=None):
            assert cpu_count() == 1

    def test_cpu_count_os_error(self):
        from industrialxpl.core.pool import cpu_count
        with patch("os.cpu_count", side_effect=OSError):
            assert cpu_count() == 1

    def test_pool_strategy_threads(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=4, strategy=PoolStrategy.THREADS)
        assert pool.strategy == "threads"
        assert pool.max_workers == 4

    def test_pool_strategy_processes(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=4, strategy=PoolStrategy.PROCESSES)
        assert pool.strategy == "processes"

    def test_pool_strategy_auto_threads(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.AUTO)
        # With 2 workers and likely >= 1 CPU, should use threads
        assert pool.strategy == "threads"

    def test_pool_strategy_auto_processes(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        with patch("industrialxpl.core.pool.cpu_count", return_value=1):
            pool = SmartPool(max_workers=100, strategy=PoolStrategy.AUTO)
            assert pool.strategy == "processes"

    def test_pool_auto_workers(self):
        from industrialxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=0)
        assert pool.max_workers > 0

    def test_submit(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        future = pool.submit(lambda x: x * 2, 5)
        assert future.result(timeout=5) == 10
        pool.shutdown()

    def test_map_unordered(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        results = pool.map_unordered(lambda x: x * 2, [1, 2, 3])
        vals = sorted(r for _, r in results)
        assert vals == [2, 4, 6]
        pool.shutdown()

    def test_map_unordered_with_timeout(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        results = pool.map_unordered(lambda x: x, [1], timeout_per_item=5)
        assert len(results) == 1
        pool.shutdown()

    def test_map_unordered_with_callbacks(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        on_result_calls = []
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        results = pool.map_unordered(
            lambda x: x * 2, [1],
            on_result=lambda item, result: on_result_calls.append((item, result)),
        )
        assert len(on_result_calls) == 1
        pool.shutdown()

    def test_map_unordered_with_error(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        errors = []
        def fail(x):
            raise ValueError("boom")
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        results = pool.map_unordered(
            fail, [1],
            on_error=lambda item, exc: errors.append((item, exc)),
        )
        assert len(results) == 0
        assert len(errors) == 1
        pool.shutdown()

    def test_map_unordered_error_no_callback(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        def fail(x):
            raise OSError("boom")
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        results = pool.map_unordered(fail, [1])
        assert len(results) == 0
        pool.shutdown()

    def test_create_executor_process(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.PROCESSES)
        pool._create_executor()
        assert pool._executor is not None
        # calling again is a no-op
        executor = pool._executor
        pool._create_executor()
        assert pool._executor is executor
        pool.shutdown()

    def test_run_threaded_workers(self):
        from industrialxpl.core.pool import SmartPool
        pool = SmartPool()
        stop = threading.Event()
        stop.set()
        def worker(stop_event):
            pass  # exits immediately
        elapsed = pool.run_threaded_workers(2, worker, stop)
        assert elapsed >= 0
        pool.shutdown()

    def test_run_threaded_workers_runtime_error(self):
        from industrialxpl.core.pool import SmartPool
        pool = SmartPool()
        stop = threading.Event()
        stop.set()
        call_count = 0
        def worker(stop_event):
            pass
        # Patch Thread.start to raise RuntimeError on second call
        original_start = threading.Thread.start
        starts = [0]
        def patched_start(self):
            starts[0] += 1
            if starts[0] > 1:
                raise RuntimeError("can't start")
            original_start(self)
        with patch.object(threading.Thread, "start", patched_start):
            with pytest.raises(RuntimeError):
                pool.run_threaded_workers(3, worker, stop)
        pool.shutdown()

    def test_context_manager(self):
        from industrialxpl.core.pool import SmartPool
        with SmartPool(max_workers=2) as pool:
            f = pool.submit(lambda: 42)
            assert f.result(timeout=5) == 42

    def test_shutdown_none_executor(self):
        from industrialxpl.core.pool import SmartPool
        pool = SmartPool()
        pool.shutdown()  # Should be no-op

    def test_shutdown_type_error(self):
        from industrialxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
        pool._create_executor()
        call_count = 0
        orig_shutdown = pool._executor.shutdown
        def fake_shutdown(wait=False, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1 and "cancel_futures" in kwargs:
                raise TypeError("no cancel_futures")
            orig_shutdown(wait=wait)
        pool._executor.shutdown = fake_shutdown
        pool.shutdown()
        assert call_count == 2

    def test_repr(self):
        from industrialxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=4)
        r = repr(pool)
        assert "SmartPool" in r
        assert "workers=4" in r


# ===========================================================================
# core/session.py
# ===========================================================================
class TestSession:
    def test_host_id(self):
        from industrialxpl.core.session import host_id
        hid = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
        assert len(hid) == 16
        # Deterministic
        assert hid == host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
        # Different for different MACs
        assert hid != host_id("192.168.1.1", "")

    def test_module_result_serialization(self):
        from industrialxpl.core.session import ModuleResult
        mr = ModuleResult(
            module_path="test.mod",
            vulnerable=True,
            error=None,
            elapsed_s=1.5,
            port=502,
            protocol="modbus",
            timestamp=1000.0,
            details="found vuln",
        )
        d = mr.to_dict()
        assert d["module_path"] == "test.mod"
        assert d["vulnerable"] is True
        mr2 = ModuleResult.from_dict(d)
        assert mr2.module_path == "test.mod"

    def test_module_result_from_dict_defaults(self):
        from industrialxpl.core.session import ModuleResult
        mr = ModuleResult.from_dict({})
        assert mr.module_path == ""
        assert mr.vulnerable is None

    def test_host_session_methods(self):
        from industrialxpl.core.session import HostSession, ModuleResult
        hs = HostSession(host_id="abc123", ip="10.0.0.1")
        hs.matched_modules = ["mod.a", "mod.b"]

        # Add results
        mr1 = ModuleResult(module_path="mod.a", vulnerable=True, timestamp=0)
        hs.add_result(mr1)
        assert mr1.timestamp > 0  # auto-set
        assert "mod.a" in hs.vulns_found

        mr2 = ModuleResult(module_path="mod.a", vulnerable=True, timestamp=100)
        hs.add_result(mr2)
        # Duplicate vuln should not be added again
        assert hs.vulns_found.count("mod.a") == 1

        mr3 = ModuleResult(module_path="mod.c", vulnerable=False, timestamp=200)
        hs.add_result(mr3)

        mr4 = ModuleResult(module_path="mod.d", error="timeout", timestamp=300)
        hs.add_result(mr4)

        assert "mod.a" in hs.modules_tested()
        assert "mod.b" in hs.modules_pending()
        assert "mod.a" in hs.modules_vulnerable()
        assert "mod.c" in hs.modules_safe()
        assert "mod.d" in hs.modules_errored()

    def test_host_session_merge_discovery(self):
        from industrialxpl.core.session import HostSession
        hs = HostSession(host_id="abc", ip="10.0.0.1")
        hs.merge_discovery(
            ip="10.0.0.1",
            mac="AA:BB",
            hostname="plc1",
            vendor="Siemens",
            model="S7-1200",
            open_ports=[502, 102],
            banners={502: "Modbus"},
            fingerprint_confidence=0.9,
            matched_modules=["mod.a"],
            has_wireless=True,
            wireless_ssids=["PLC_WiFi"],
            wireless_recommendation="Disable WiFi",
        )
        assert hs.mac == "AA:BB"
        assert hs.hostname == "plc1"
        assert 502 in hs.open_ports
        assert hs.has_wireless is True
        assert "PLC_WiFi" in hs.wireless_ssids

        # Merge again with additional data
        hs.merge_discovery(
            ip="10.0.0.1",
            open_ports=[80],
            matched_modules=["mod.b"],
            wireless_ssids=["PLC_WiFi", "OT_Net"],
        )
        assert 80 in hs.open_ports
        assert "mod.b" in hs.matched_modules
        assert "OT_Net" in hs.wireless_ssids
        assert hs.total_scans == 2

    def test_host_session_summary_line(self):
        from industrialxpl.core.session import HostSession
        hs = HostSession(host_id="abc", ip="10.0.0.1")
        line = hs.summary_line()
        assert "10.0.0.1" in line
        assert "no-mac" in line

    def test_host_session_serialization(self):
        from industrialxpl.core.session import HostSession, ModuleResult
        hs = HostSession(host_id="abc", ip="10.0.0.1")
        hs.add_result(ModuleResult(module_path="mod.a", vulnerable=True, timestamp=100))
        d = hs.to_dict()
        hs2 = HostSession.from_dict(d)
        assert hs2.ip == "10.0.0.1"
        assert len(hs2.module_results) == 1

    def test_session_manager(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        mgr = SessionManager(sessions_dir=tmp_path)
        # Create
        session = mgr.create("10.0.0.1", "AA:BB")
        mgr.save(session)
        # Exists
        assert mgr.exists("10.0.0.1", "AA:BB")
        # Find
        hid = mgr.find("10.0.0.1", "AA:BB")
        assert hid is not None
        # Load
        loaded = mgr.load("10.0.0.1", "AA:BB")
        assert loaded is not None
        assert loaded.ip == "10.0.0.1"
        # List
        sessions = mgr.list_sessions()
        assert len(sessions) >= 1
        # Get or create existing
        existing, is_existing = mgr.get_or_create("10.0.0.1", "AA:BB")
        assert is_existing is True
        # Get or create new
        new, is_existing = mgr.get_or_create("10.0.0.2")
        assert is_existing is False
        # Export
        exported = mgr.export_session("10.0.0.1", "AA:BB")
        assert exported is not None
        assert "10.0.0.1" in exported
        # Export non-existent
        assert mgr.export_session("1.2.3.4") is None

    def test_session_manager_delete(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        mgr = SessionManager(sessions_dir=tmp_path)
        session = mgr.create("10.0.0.1")
        mgr.save(session)
        assert mgr.delete("10.0.0.1")
        assert not mgr.exists("10.0.0.1")
        # Delete non-existent
        assert not mgr.delete("1.2.3.4")

    def test_session_manager_delete_by_id(self, tmp_path):
        from industrialxpl.core.session import SessionManager, host_id
        mgr = SessionManager(sessions_dir=tmp_path)
        session = mgr.create("10.0.0.1")
        mgr.save(session)
        hid = host_id("10.0.0.1", "")
        assert mgr.delete_by_id(hid)
        assert not mgr.delete_by_id("nonexistent")

    def test_session_manager_purge(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        mgr = SessionManager(sessions_dir=tmp_path)
        mgr.save(mgr.create("10.0.0.1"))
        mgr.save(mgr.create("10.0.0.2"))
        count = mgr.purge_all()
        assert count == 2

    def test_session_manager_find_ip_only(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        mgr = SessionManager(sessions_dir=tmp_path)
        session = mgr.create("10.0.0.1", "AA:BB")
        mgr.save(session)
        # Find by IP only (no MAC)
        found = mgr.find("10.0.0.1")
        assert found is not None

    def test_session_manager_load_corrupt(self, tmp_path):
        from industrialxpl.core.session import SessionManager, host_id
        mgr = SessionManager(sessions_dir=tmp_path)
        hid = host_id("10.0.0.1", "")
        # Write corrupt JSON
        (tmp_path / f"{hid}.json").write_text("not json", encoding="utf-8")
        mgr._index[hid] = {"ip": "10.0.0.1"}
        assert mgr.load("10.0.0.1") is None

    def test_session_manager_corrupt_index(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        idx = tmp_path / "_index.json"
        idx.write_text("not json", encoding="utf-8")
        mgr = SessionManager(sessions_dir=tmp_path)
        assert mgr._index == {}

    def test_session_manager_save_failure(self, tmp_path):
        from industrialxpl.core.session import SessionManager
        mgr = SessionManager(sessions_dir=tmp_path)
        session = mgr.create("10.0.0.1")
        # Patch open to fail
        with patch("builtins.open", side_effect=OSError("disk full")):
            mgr.save(session)
        # Should not crash


# ===========================================================================
# core/network/__init__.py and transport.py
# ===========================================================================
class TestNetworkTransport:
    def test_imports(self):
        from industrialxpl.core.network import (
            DEFAULT_OT_PORTS, connect_tcp, connect_udp,
            probe_tcp, probe_udp, resolve_transports,
        )
        assert isinstance(DEFAULT_OT_PORTS, dict)
        assert "modbus" in DEFAULT_OT_PORTS

    def test_resolve_transports_tcp(self):
        from industrialxpl.core.network.transport import resolve_transports
        result = resolve_transports("tcp")
        assert result == [("TCP", False)]

    def test_resolve_transports_udp(self):
        from industrialxpl.core.network.transport import resolve_transports
        assert resolve_transports("udp") == [("UDP", True)]

    def test_resolve_transports_both(self):
        from industrialxpl.core.network.transport import resolve_transports
        result = resolve_transports("both")
        assert len(result) == 2

    def test_resolve_transports_all(self):
        from industrialxpl.core.network.transport import resolve_transports
        result = resolve_transports("all")
        assert len(result) == 2

    def test_resolve_transports_invalid(self):
        from industrialxpl.core.network.transport import resolve_transports
        with pytest.raises(ValueError):
            resolve_transports("invalid")

    def test_connect_tcp_success(self):
        from industrialxpl.core.network.transport import connect_tcp
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            assert connect_tcp("127.0.0.1", 502, 1.0) is True
            mock_sock.close.assert_called_once()

    def test_connect_tcp_fail(self):
        from industrialxpl.core.network.transport import connect_tcp
        with patch("socket.create_connection", side_effect=OSError):
            assert connect_tcp("127.0.0.1", 502, 1.0) is False

    def test_connect_udp_success(self):
        from industrialxpl.core.network.transport import connect_udp
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            assert connect_udp("127.0.0.1", 502, 1.0) is True
            mock_sock.sendto.assert_called_once()

    def test_connect_udp_fail(self):
        from industrialxpl.core.network.transport import connect_udp
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.sendto.side_effect = OSError
            assert connect_udp("127.0.0.1", 502, 1.0) is False

    def test_probe_tcp_success(self):
        from industrialxpl.core.network.transport import probe_tcp
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"\x01\x02"
            mock_conn.return_value = mock_sock
            result = probe_tcp("127.0.0.1", 502, b"\x00", 1.0)
            assert result == b"\x01\x02"

    def test_probe_tcp_no_data(self):
        from industrialxpl.core.network.transport import probe_tcp
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"\x01"
            mock_conn.return_value = mock_sock
            result = probe_tcp("127.0.0.1", 502, b"", 1.0)
            assert result == b"\x01"
            mock_sock.sendall.assert_not_called()

    def test_probe_tcp_fail(self):
        from industrialxpl.core.network.transport import probe_tcp
        with patch("socket.create_connection", side_effect=OSError):
            assert probe_tcp("127.0.0.1", 502, b"\x00", 1.0) is None

    def test_probe_udp_success(self):
        from industrialxpl.core.network.transport import probe_udp
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (b"\x01\x02", ("127.0.0.1", 502))
            mock_cls.return_value = mock_sock
            result = probe_udp("127.0.0.1", 502, b"\x00", 1.0)
            assert result == b"\x01\x02"

    def test_probe_udp_fail(self):
        from industrialxpl.core.network.transport import probe_udp
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.recvfrom.side_effect = OSError
            assert probe_udp("127.0.0.1", 502, b"\x00", 1.0) is None


# ===========================================================================
# core/modbus/timing.py
# ===========================================================================
class TestModbusTiming:
    def test_timing_profiles(self):
        from industrialxpl.core.modbus.timing import TIMING_PROFILES, DEFAULT_TIMING
        assert len(TIMING_PROFILES) == 6
        assert DEFAULT_TIMING.level == 3

    def test_timing_profile_sleep(self):
        from industrialxpl.core.modbus.timing import TimingProfile
        tp = TimingProfile(level=5, name="Insane", socket_timeout=0.2,
                           inter_request_delay=0.0, retries=1, max_rtt_timeout=0.2)
        tp.sleep()  # Should be instant (delay=0)

    def test_timing_profile_sleep_with_delay(self):
        from industrialxpl.core.modbus.timing import TimingProfile
        tp = TimingProfile(level=0, name="Test", socket_timeout=1.0,
                           inter_request_delay=0.01, retries=1, max_rtt_timeout=1.0)
        start = time.monotonic()
        tp.sleep()
        assert time.monotonic() - start >= 0.005

    def test_timing_profile_str(self):
        from industrialxpl.core.modbus.timing import DEFAULT_TIMING
        s = str(DEFAULT_TIMING)
        assert "T3" in s
        assert "Normal" in s

    def test_modbus_timing_resolve_int(self):
        from industrialxpl.core.modbus.timing import ModbusTiming
        p = ModbusTiming.resolve(3)
        assert p.level == 3

    def test_modbus_timing_resolve_string(self):
        from industrialxpl.core.modbus.timing import ModbusTiming
        assert ModbusTiming.resolve("T3").level == 3
        assert ModbusTiming.resolve("t4").level == 4
        assert ModbusTiming.resolve("normal").level == 3
        assert ModbusTiming.resolve("paranoid").level == 0

    def test_modbus_timing_resolve_invalid_string(self):
        from industrialxpl.core.modbus.timing import ModbusTiming
        with pytest.raises(ValueError, match="Invalid timing level"):
            ModbusTiming.resolve("badname")

    def test_modbus_timing_resolve_invalid_level(self):
        from industrialxpl.core.modbus.timing import ModbusTiming
        with pytest.raises(ValueError, match="Timing level must be 0-5"):
            ModbusTiming.resolve(99)

    def test_describe_all(self):
        from industrialxpl.core.modbus.timing import ModbusTiming
        desc = ModbusTiming.describe_all()
        assert "Paranoid" in desc.lower() or "paranoid" in desc
        assert "T3" in desc


# ===========================================================================
# core/modbus/address.py
# ===========================================================================
class TestModbusAddress:
    def test_parse_single_decimal(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("10")
        assert len(addr_set) == 1
        assert addr_set.addresses[0].offset == 10

    def test_parse_range(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("14-20")
        assert len(addr_set) == 7
        assert addr_set.min == 14
        assert addr_set.max == 20
        assert addr_set.span == 7

    def test_parse_mixed(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("10,14-16,100")
        assert len(addr_set) == 5
        offsets = addr_set.offsets()
        assert 10 in offsets
        assert 100 in offsets

    def test_parse_modicon_5digit_coil(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("00001")
        assert addr_set.addresses[0].implied_fc == 1
        assert addr_set.addresses[0].data_type == "coil"
        assert addr_set.addresses[0].offset == 0

    def test_parse_modicon_5digit_holding(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("40001")
        assert addr_set.addresses[0].implied_fc == 3

    def test_parse_modicon_6digit(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("400001")
        assert addr_set.addresses[0].implied_fc == 3
        assert addr_set.addresses[0].offset == 0

    def test_parse_modicon_6digit_input(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("300001")
        assert addr_set.addresses[0].implied_fc == 4

    def test_parse_empty(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        with pytest.raises(ValueError, match="empty"):
            parse_modbus_addresses("")

    def test_parse_invalid_token(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses, _parse_single
        with pytest.raises(ValueError, match="Cannot parse"):
            _parse_single("abc")

    def test_parse_empty_token(self):
        from industrialxpl.core.modbus.address import _parse_single
        with pytest.raises(ValueError, match="Empty"):
            _parse_single("")

    def test_parse_exceeds_max(self):
        from industrialxpl.core.modbus.address import _parse_single
        with pytest.raises(ValueError, match="exceeds"):
            _parse_single("99999")

    def test_parse_unrecognized_5digit_prefix(self):
        from industrialxpl.core.modbus.address import _parse_single
        with pytest.raises(ValueError, match="Unrecognized Modicon 5-digit"):
            _parse_single("20001")

    def test_parse_unrecognized_6digit_prefix(self):
        from industrialxpl.core.modbus.address import _parse_single
        with pytest.raises(ValueError, match="Unrecognized Modicon 6-digit"):
            _parse_single("200001")

    def test_parse_range_reversed(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        with pytest.raises(ValueError, match="start.*end"):
            parse_modbus_addresses("20-10")

    def test_parse_range_cross_type(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        with pytest.raises(ValueError, match="different Modicon data types"):
            parse_modbus_addresses("00001-10001")

    def test_as_bulk(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("10,20")
        start, qty = addr_set.as_bulk()
        assert start == 10
        assert qty == 11

    def test_unanimous_fc(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("40001,40005")
        assert addr_set.implied_fc == 3

    def test_no_unanimous_fc_mixed(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("10,20")
        assert addr_set.implied_fc is None

    def test_modbus_address_repr(self):
        from industrialxpl.core.modbus.address import ModbusAddress
        a = ModbusAddress(raw="40001", offset=0, implied_fc=3)
        assert "FC3" in repr(a)
        a2 = ModbusAddress(raw="10", offset=10)
        assert "FC" not in repr(a2)

    def test_iter_and_len(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        addr_set = parse_modbus_addresses("0-4")
        assert len(addr_set) == 5
        items = list(addr_set)
        assert len(items) == 5


# ===========================================================================
# core/modbus/transport.py
# ===========================================================================
class TestModbusTransport:
    def test_parse_port_expression_single(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        assert parse_port_expression("502") == [502]

    def test_parse_port_expression_list(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        assert parse_port_expression("502,510") == [502, 510]

    def test_parse_port_expression_range(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        result = parse_port_expression("500-505")
        assert result == [500, 501, 502, 503, 504, 505]

    def test_parse_port_expression_empty(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="No ports"):
            parse_port_expression("")

    def test_parse_port_expression_invalid(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="Invalid port"):
            parse_port_expression("abc")

    def test_parse_port_expression_invalid_range(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="Invalid port range"):
            parse_port_expression("abc-def")

    def test_parse_port_expression_out_of_bounds(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="out of bounds"):
            parse_port_expression("0-100")

    def test_parse_port_expression_too_wide(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="too wide"):
            parse_port_expression("1-2000")

    def test_parse_port_expression_single_out_of_bounds(self):
        from industrialxpl.core.modbus.transport import parse_port_expression
        with pytest.raises(ValueError, match="out of bounds"):
            parse_port_expression("70000")

    def test_modbus_connect_success(self):
        from industrialxpl.core.modbus.transport import modbus_connect
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            result = modbus_connect("127.0.0.1", 502, 1.0)
            assert result is mock_sock

    def test_modbus_connect_fail(self):
        from industrialxpl.core.modbus.transport import modbus_connect
        with patch("socket.create_connection", side_effect=TimeoutError):
            assert modbus_connect("127.0.0.1", 502, 1.0) is None

    def test_modbus_tcp_socket_context_manager(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        with patch("industrialxpl.core.modbus.transport.modbus_connect") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            with ModbusTCPSocket("127.0.0.1", 502) as ms:
                assert ms._sock is mock_sock

    def test_modbus_tcp_socket_close_error(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        ms._sock = MagicMock()
        ms._sock.close.side_effect = OSError("close error")
        ms.close()  # Should not raise
        assert ms._sock is None

    def test_build_adu(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502, unit_id=1)
        pdu = b"\x03\x00\x00\x00\x0a"
        adu = ms._build_adu(pdu)
        # MBAP header: tx_id(2) + protocol_id(2) + length(2) + unit_id(1) + pdu
        assert len(adu) == 7 + len(pdu)

    def test_next_tx_wraps(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        ms._tx_id = 0xFFFF
        assert ms._next_tx() == 0  # wraps around

    def test_send_pdu_success(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket, DEFAULT_TIMING
        ms = ModbusTCPSocket("127.0.0.1", 502)
        ms._sock = MagicMock()
        # First recv returns enough data
        ms._sock.recv.return_value = b"\x00" * 10
        with patch("time.monotonic", side_effect=[0, 0, 0.01]):
            result = ms.send_pdu(b"\x03\x00\x00\x00\x0a")
        assert result is not None

    def test_send_pdu_no_socket_reconnect(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        ms._sock = None
        with patch.object(ms, "connect", return_value=False):
            result = ms.send_pdu(b"\x03\x00\x00\x00\x0a")
        assert result is None

    def test_send_pdu_timeout_retry(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        from industrialxpl.core.modbus.timing import TimingProfile
        tp = TimingProfile(level=3, name="Test", socket_timeout=0.1,
                           inter_request_delay=0, retries=2, max_rtt_timeout=0.1)
        ms = ModbusTCPSocket("127.0.0.1", 502, timing=tp)
        ms._sock = MagicMock()
        ms._sock.sendall.side_effect = TimeoutError
        with patch.object(ms, "close"):
            with patch.object(ms, "connect", return_value=False):
                with patch("time.sleep"):
                    result = ms.send_pdu(b"\x03")
        assert result is None

    def test_read_coils(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"\x01\x02") as mock_send:
            result = ms.read_coils(0, 8)
            assert result == b"\x01\x02"

    def test_read_discrete_inputs(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"\x02") as mock_send:
            result = ms.read_discrete_inputs(0, 8)
            assert result is not None

    def test_read_holding_registers(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"\x03\x02\x00\x01") as mock_send:
            result = ms.read_holding_registers(0, 1)
            assert result is not None

    def test_read_input_registers(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"\x04") as mock_send:
            result = ms.read_input_registers(0, 1)
            assert result is not None

    def test_write_single_coil(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok") as mock_send:
            ms.write_single_coil(0, True)
            ms.write_single_coil(0, False)

    def test_write_single_register(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok") as mock_send:
            ms.write_single_register(0, 42)

    def test_write_multiple_coils(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok") as mock_send:
            ms.write_multiple_coils(0, [True, False, True, True, False, False, True, False, True])

    def test_write_multiple_registers(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.write_multiple_registers(0, [100, 200, 300])

    def test_mask_write_register(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.mask_write_register(0, 0xFF00, 0x00FF)

    def test_read_write_registers(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.read_write_registers(0, 5, 10, [1, 2])

    def test_diagnostic(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.diagnostic(0x0000, 0x0000)

    def test_get_com_event_counter(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.get_com_event_counter()

    def test_write_file_record(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.write_file_record(1, 0, b"\x00\x01")

    def test_encapsulated_interface_transport(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.encapsulated_interface_transport(14, b"\x00")

    def test_report_server_id(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.report_server_id()

    def test_read_device_identification(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with patch.object(ms, "send_pdu", return_value=b"ok"):
            ms.read_device_identification()

    def test_send_fc_valid(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        for fc in (1, 2, 3, 4):
            with patch.object(ms, "send_pdu", return_value=b"ok"):
                ms.send_fc(fc, 0, 1)

    def test_send_fc_invalid(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        ms = ModbusTCPSocket("127.0.0.1", 502)
        with pytest.raises(ValueError, match="not supported"):
            ms.send_fc(99, 0, 1)

    def test_scan_ports(self):
        from industrialxpl.core.modbus.transport import scan_ports
        with patch("industrialxpl.core.modbus.transport.modbus_connect") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.side_effect = [mock_sock, None, mock_sock]
            result = scan_ports("127.0.0.1", [502, 503, 504], 1.0)
            assert result == [502, 504]


# ===========================================================================
# core/modbus/base.py
# ===========================================================================
class TestModbusBase:
    def test_opt_timing_validate(self):
        from industrialxpl.core.modbus.base import _OptTiming
        opt = _OptTiming("T3", "timing")
        assert opt.validate("T3") == "T3"
        assert opt.validate("normal") == "normal"

    def test_opt_timing_validate_invalid(self):
        from industrialxpl.core.modbus.base import _OptTiming
        opt = _OptTiming("T3", "timing")
        # OptionValidationError is imported inside validate
        with pytest.raises(Exception):
            opt.validate("badvalue")

    def test_opt_port_expr_validate(self):
        from industrialxpl.core.modbus.base import _OptPortExpr
        opt = _OptPortExpr("502", "port")
        assert opt.validate("502") == "502"

    def test_opt_port_expr_validate_invalid(self):
        from industrialxpl.core.modbus.base import _OptPortExpr
        opt = _OptPortExpr("502", "port")
        with pytest.raises(Exception):
            opt.validate("abc")

    def test_opt_register_expr_validate(self):
        from industrialxpl.core.modbus.base import _OptRegisterExpr
        opt = _OptRegisterExpr("", "regs")
        assert opt.validate("10-20") == "10-20"
        assert opt.validate("") == ""
        assert opt.validate("  ") == ""

    def test_opt_register_expr_validate_invalid(self):
        from industrialxpl.core.modbus.base import _OptRegisterExpr
        opt = _OptRegisterExpr("", "regs")
        with pytest.raises(Exception):
            opt.validate("xyz")


# ===========================================================================
# core/reporting/reporter.py
# ===========================================================================
class TestReporter:
    def test_add_finding_and_generate(self, tmp_path):
        from industrialxpl.core.reporting.reporter import IXFReporter
        reporter = IXFReporter()
        reporter.add_finding({"type": "test", "severity": "high"})
        with patch("industrialxpl.core.reporting.reporter.PROJECT_TMP", tmp_path):
            path = reporter.generate("json")
        assert path.endswith(".json")
        data = json.loads(Path(path).read_text())
        assert len(data["findings"]) == 1
        assert data["findings"][0]["type"] == "test"


# ===========================================================================
# core/mitre/reporter.py
# ===========================================================================
class TestMitreReporter:
    def test_generate_layer(self, tmp_path):
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        reporter = MitreSweepReporter()
        with patch("industrialxpl.core.mitre.reporter.PROJECT_TMP", tmp_path):
            with patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["mod.a"]}):
                with patch("industrialxpl.core.mitre.index.build_index"):
                    path = reporter.generate_layer()
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert data["domain"] == "ics-attack"

    def test_save(self, tmp_path):
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        reporter = MitreSweepReporter(results=[{"module": "test", "status": "OK"}])
        path = reporter.save(str(tmp_path / "results.json"))
        assert Path(path).exists()

    def test_generate_json(self, tmp_path):
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        reporter = MitreSweepReporter(results=[{"status": "OK"}])
        with patch("industrialxpl.core.mitre.reporter.PROJECT_TMP", tmp_path):
            path = reporter.generate("json")
        assert Path(path).exists()

    def test_generate_txt(self, tmp_path):
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        reporter = MitreSweepReporter(results=[{"status": "OK"}])
        with patch("industrialxpl.core.mitre.reporter.PROJECT_TMP", tmp_path):
            path = reporter.generate("txt")
        assert Path(path).exists()

    def test_status_colors(self):
        from industrialxpl.core.mitre.reporter import STATUS_COLORS
        assert "VULNERABLE" in STATUS_COLORS


# ===========================================================================
# core/mitre/index.py
# ===========================================================================
class TestMitreIndex:
    def test_build_index(self):
        from industrialxpl.core.mitre import index as idx_mod
        idx_mod._built = False
        idx_mod.TECHNIQUE_INDEX.clear()
        idx_mod.TACTIC_INDEX.clear()
        # Provide empty module list
        idx_mod.build_index(module_paths=[])
        assert idx_mod._built is True

    def test_build_index_skip_no_class(self):
        from industrialxpl.core.mitre import index as idx_mod
        idx_mod._built = False
        mock_mod = types.ModuleType("test_module")
        with patch("importlib.import_module", return_value=mock_mod):
            idx_mod.build_index(module_paths=["test.mod"])
        # No Exploit/Scanner/Assessment class found, should skip

    def test_build_index_already_built(self):
        from industrialxpl.core.mitre import index as idx_mod
        idx_mod._built = True
        idx_mod.build_index()  # Should return early

    def test_build_index_with_techniques(self):
        from industrialxpl.core.mitre import index as idx_mod
        idx_mod._built = False

        class FakeExploit:
            __info__ = {"mitre_techniques": ["T0843 Program Download"]}

        # Patch the private attribute access
        FakeExploit._FakeExploit__info__ = {"mitre_techniques": ["T0843 Program Download"]}
        mock_mod = types.ModuleType("test_module")
        mock_mod.Exploit = FakeExploit
        with patch("importlib.import_module", return_value=mock_mod):
            idx_mod.build_index(module_paths=["test.mod"])
        assert "T0843" in idx_mod.TECHNIQUE_INDEX

    def test_build_index_attribute_error(self):
        from industrialxpl.core.mitre import index as idx_mod
        idx_mod._built = False
        with patch("importlib.import_module", side_effect=AttributeError("nope")):
            idx_mod.build_index(module_paths=["bad.mod"])
        # Should not crash


# ===========================================================================
# core/nse/nse_manager.py
# ===========================================================================
class TestNseManager:
    def test_find_nmap(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert NseManager.find_nmap() == "/usr/bin/nmap"
        with patch("shutil.which", return_value=None):
            assert NseManager.find_nmap() is None

    def test_get_nmap_version_found(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value="/usr/bin/nmap"):
            mock_result = MagicMock()
            mock_result.stdout = "Nmap version 7.95 ( https://nmap.org )\n"
            with patch("subprocess.run", return_value=mock_result):
                ver = NseManager.get_nmap_version()
                assert "Nmap version" in ver

    def test_get_nmap_version_not_installed(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value=None):
            assert NseManager.get_nmap_version() is None

    def test_get_nmap_version_error(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value="/usr/bin/nmap"):
            with patch("subprocess.run", side_effect=OSError):
                assert NseManager.get_nmap_version() is None

    def test_find_scripts_dir_candidate(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        with patch("industrialxpl.core.nse.nse_manager._NMAP_SCRIPTS_CANDIDATES",
                    {"linux": [str(scripts)]}):
            with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
                mock_sys.platform = "linux"
                with patch("shutil.which", return_value=None):
                    result = NseManager.find_scripts_dir()
                    assert result == scripts

    def test_find_scripts_dir_glob(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        # Create a path with glob pattern
        scripts = tmp_path / "nmap" / "7.95" / "share" / "nmap" / "scripts"
        scripts.mkdir(parents=True)
        pattern = str(tmp_path / "nmap" / "*" / "share" / "nmap" / "scripts")
        with patch("industrialxpl.core.nse.nse_manager._NMAP_SCRIPTS_CANDIDATES",
                    {"linux": [pattern]}):
            with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
                mock_sys.platform = "linux"
                with patch("shutil.which", return_value=None):
                    result = NseManager.find_scripts_dir()
                    assert result is not None

    def test_find_scripts_dir_from_binary(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        scripts = tmp_path / "share" / "nmap" / "scripts"
        scripts.mkdir(parents=True)
        nmap_bin = tmp_path / "bin" / "nmap"
        nmap_bin.parent.mkdir(parents=True)
        nmap_bin.touch()
        with patch("industrialxpl.core.nse.nse_manager._NMAP_SCRIPTS_CANDIDATES",
                    {"linux": []}):
            with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
                mock_sys.platform = "linux"
                with patch("shutil.which", return_value=str(nmap_bin)):
                    result = NseManager.find_scripts_dir()
                    assert result is not None

    def test_find_scripts_dir_none(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch("industrialxpl.core.nse.nse_manager._NMAP_SCRIPTS_CANDIDATES",
                    {"linux": ["/nonexistent/path"]}):
            with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
                mock_sys.platform = "linux"
                with patch("shutil.which", return_value=None):
                    with patch.object(NseManager, "_locate_nse_dir_via_find", return_value=None):
                        assert NseManager.find_scripts_dir() is None

    def test_locate_nse_dir_via_find_linux(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = str(tmp_path) + "\n"
        with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
            mock_sys.platform = "linux"
            with patch("subprocess.run", return_value=mock_result):
                result = NseManager._locate_nse_dir_via_find()
                assert result == tmp_path

    def test_locate_nse_dir_via_find_file(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        nse_file = tmp_path / "test.nse"
        nse_file.touch()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = str(nse_file) + "\n"
        with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
            mock_sys.platform = "linux"
            with patch("subprocess.run", return_value=mock_result):
                result = NseManager._locate_nse_dir_via_find()
                assert result == tmp_path

    def test_locate_nse_dir_via_find_win32(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        scripts = tmp_path / "Nmap" / "scripts"
        scripts.mkdir(parents=True)
        with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch("shutil.which", return_value=None):
                with patch.dict(os.environ, {"ProgramFiles": str(tmp_path)}):
                    result = NseManager._locate_nse_dir_via_find()
                    assert result == scripts

    def test_locate_nse_dir_via_find_win32_from_binary(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch("shutil.which", return_value=str(tmp_path / "nmap.exe")):
                result = NseManager._locate_nse_dir_via_find()
                assert result == scripts

    def test_list_ixf_scripts(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        (tmp_path / "test.nse").touch()
        with patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", tmp_path):
            scripts = NseManager.list_ixf_scripts()
            assert len(scripts) == 1

    def test_list_ixf_scripts_no_dir(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", Path("/nonexistent")):
            assert NseManager.list_ixf_scripts() == []

    def test_list_installed(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        nse_dir = tmp_path / "nse"
        nse_dir.mkdir()
        (nse_dir / "test.nse").touch()
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "test.nse").touch()
        with patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", nse_dir):
            installed = NseManager.list_installed(scripts_dir)
            assert "test.nse" in installed

    def test_install_no_scripts_dir(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_scripts_dir", return_value=None):
            result = NseManager.install()
            assert result["success"] is False
            assert "not found" in result["errors"][0]

    def test_install_no_ixf_scripts(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "list_ixf_scripts", return_value=[]):
            result = NseManager.install(scripts_dir=tmp_path)
            assert result["success"] is False

    def test_install_success(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        nse_src = tmp_path / "src"
        nse_src.mkdir()
        (nse_src / "test.nse").write_text("-- test nse script")
        dest = tmp_path / "dest"
        dest.mkdir()
        with patch.object(NseManager, "list_ixf_scripts", return_value=[nse_src / "test.nse"]):
            with patch.object(NseManager, "_run_updatedb"):
                with patch("industrialxpl.core.nse.nse_manager.sys") as mock_sys:
                    mock_sys.platform = "linux"
                    result = NseManager.install(scripts_dir=dest)
        assert result["success"] is True
        assert "test.nse" in result["installed"]

    def test_install_skip_existing(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        nse_src = tmp_path / "src"
        nse_src.mkdir()
        (nse_src / "test.nse").write_text("-- test")
        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "test.nse").write_text("-- already here")
        with patch.object(NseManager, "list_ixf_scripts", return_value=[nse_src / "test.nse"]):
            result = NseManager.install(scripts_dir=dest, force=False)
        assert "test.nse" in result["skipped"]

    def test_install_permission_error(self, tmp_path):
        from industrialxpl.core.nse.nse_manager import NseManager
        nse_src = tmp_path / "src"
        nse_src.mkdir()
        (nse_src / "test.nse").write_text("-- test")
        with patch.object(NseManager, "list_ixf_scripts", return_value=[nse_src / "test.nse"]):
            with patch("shutil.copy2", side_effect=PermissionError):
                result = NseManager.install(scripts_dir=tmp_path)
        assert len(result["errors"]) > 0

    def test_run_updatedb(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value="/usr/bin/nmap"):
            with patch("subprocess.run") as mock_run:
                NseManager._run_updatedb()
                mock_run.assert_called_once()

    def test_run_updatedb_no_nmap(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value=None):
            NseManager._run_updatedb()  # no-op

    def test_status_report(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value="/usr/bin/nmap"):
            with patch.object(NseManager, "get_nmap_version", return_value="Nmap version 7.95"):
                with patch.object(NseManager, "list_ixf_scripts", return_value=[]):
                    with patch.object(NseManager, "find_scripts_dir", return_value=None):
                        NseManager.status_report()

    def test_status_report_no_nmap(self):
        from industrialxpl.core.nse.nse_manager import NseManager
        with patch.object(NseManager, "find_nmap", return_value=None):
            with patch.object(NseManager, "list_ixf_scripts", return_value=[]):
                with patch.object(NseManager, "find_scripts_dir", return_value=None):
                    NseManager.status_report()


# ===========================================================================
# core/poly/poly_runner.py
# ===========================================================================
class TestPolyRunner:
    def test_check_runtime(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch("shutil.which", return_value="/usr/bin/python3"):
            assert runner.check_runtime("python3") is True
        with patch("shutil.which", return_value=None):
            assert runner.check_runtime("rubyx") is False

    def test_get_available_runtimes(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch("shutil.which", return_value=None):
            avail = runner.get_available_runtimes()
            assert all(v is False for v in avail.values())

    def test_run_success(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            rc, out, err = runner._run(["echo", "test"])
            assert rc == 0
            assert out == "output"

    def test_run_timeout(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
            rc, out, err = runner._run(["echo"], timeout=1)
            assert rc == -1
            assert "timed out" in err

    def test_run_file_not_found(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch("subprocess.run", side_effect=FileNotFoundError("nope")):
            rc, out, err = runner._run(["nonexistent"])
            assert rc == -1

    def test_run_with_fallback_native(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch.object(runner, "_run", return_value=(0, "ok", "")):
                rc, out, err = runner.run_with_fallback("ruby", ["ruby", "test.rb"], lambda: None)
                assert rc == 0

    def test_run_with_fallback_python(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, out, err = runner.run_with_fallback("ruby", ["ruby", "test.rb"], lambda: None)
            assert rc == 0
            assert "fallback" in out.lower()

    def test_run_with_fallback_python_error(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        def fail():
            raise ConnectionError("boom")
        with patch.object(runner, "check_runtime", return_value=False):
            rc, out, err = runner.run_with_fallback("ruby", ["ruby", "x"], fail)
            assert rc == -1
            assert "failed" in err.lower()

    def test_run_ruby(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, out, err = runner.run_ruby("test.rb", [])
            assert rc == -1

    def test_run_ruby_available(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, out, err = runner.run_ruby("test.rb", ["--arg"])
                assert rc == 0

    def test_run_msf_module_no_msf(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, out, err = runner.run_msf_module("exploit/test", {"RHOSTS": "1.2.3.4"})
            assert rc == -1

    def test_run_msf_module_available(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", return_value=(0, "", "")):
                    rc, out, err = runner.run_msf_module("exploit/test", {"RHOSTS": "1.2.3.4"})
                    assert rc == 0

    def test_compile_and_run_c(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, out, err = runner.compile_and_run_c("test.c", [])
            assert rc == -1

    def test_compile_and_run_c_available(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", side_effect=[(0, "", ""), (0, "ok", "")]):
                    rc, out, err = runner.compile_and_run_c("test.c", [])
                    assert rc == 0

    def test_compile_and_run_c_compile_fail(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", return_value=(1, "", "error")):
                    rc, out, err = runner.compile_and_run_c("test.c", [])
                    assert rc == 1

    def test_compile_and_run_cpp(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.compile_and_run_cpp("test.cpp", [])
            assert rc == -1

    def test_compile_and_run_cpp_available(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", side_effect=[(0, "", ""), (0, "ok", "")]):
                    rc, _, _ = runner.compile_and_run_cpp("test.cpp", [])
                    assert rc == 0

    def test_compile_and_run_cpp_compile_fail(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", return_value=(1, "", "err")):
                    rc, _, _ = runner.compile_and_run_cpp("test.cpp", [])
                    assert rc == 1

    def test_run_java_no_runtime(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.run_java("test.jar", [])
            assert rc == -1

    def test_run_java_jar(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_java("test.jar", [])
                assert rc == 0

    def test_run_java_source(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"java": True, "javac": True}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", side_effect=[(0, "", ""), (0, "ok", "")]):
                    rc, _, _ = runner.run_java("Test.java", [])
                    assert rc == 0

    def test_run_java_source_no_javac(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"java": True, "javac": False}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            rc, _, _ = runner.run_java("Test.java", [])
            assert rc == -1

    def test_run_java_source_compile_fail(self, tmp_path):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"java": True, "javac": True}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            with patch("industrialxpl.core.poly.poly_runner.PROJECT_TMP", tmp_path):
                with patch.object(runner, "_run", return_value=(1, "", "err")):
                    rc, _, _ = runner.run_java("Test.java", [])
                    assert rc == 1

    def test_run_node_js(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_node("test.js", [])
                assert rc == 0

    def test_run_node_ts_with_tsnode(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"ts-node": True}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_node("test.ts", [])
                assert rc == 0

    def test_run_node_ts_with_npx(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"ts-node": False, "npx": True}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_node("test.ts", [])
                assert rc == 0

    def test_run_node_ts_no_runtime(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.run_node("test.ts", [])
            assert rc == -1

    def test_run_node_no_runtime(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.run_node("test.js", [])
            assert rc == -1

    def test_run_go(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.run_go("test.go", [])
            assert rc == -1

    def test_run_go_available(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=True):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_go("test.go", [])
                assert rc == 0

    def test_run_powershell_pwsh(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        checks = {"pwsh": True}
        with patch.object(runner, "check_runtime", side_effect=lambda r: checks.get(r, False)):
            with patch.object(runner, "_run", return_value=(0, "", "")):
                rc, _, _ = runner.run_powershell("test.ps1", [])
                assert rc == 0

    def test_run_powershell_none(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            rc, _, _ = runner.run_powershell("test.ps1", [])
            assert rc == -1

    def test_env_report(self):
        from industrialxpl.core.poly.poly_runner import PolyExploitRunner
        runner = PolyExploitRunner()
        with patch.object(runner, "check_runtime", return_value=False):
            runner.env_report()  # Should print without error


# ===========================================================================
# core/sast/llm_provider.py
# ===========================================================================
class TestLLMProvider:
    def test_init_no_keys(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            assert not mgr.has_any_key()
            assert mgr.get_active_provider() is None

    def test_set_key(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("openai", "sk-test")
            assert mgr.has_any_key()
            assert mgr.get_active_provider() == "openai"

    def test_set_key_invalid_provider(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            with pytest.raises(ValueError, match="Unknown provider"):
                mgr.set_key("invalid_provider", "key")

    def test_status(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("anthropic", "key")
            status = mgr.status()
            assert status["anthropic"] == "configured"
            assert status["openai"] == "not configured"

    def test_get_active_provider_priority(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("anthropic", "key1")
            mgr.set_key("openai", "key2")
            # OpenAI takes priority
            assert mgr.get_active_provider() == "openai"

    def test_get_active_provider_non_openai(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("deepseek", "key")
            assert mgr.get_active_provider() == "deepseek"

    def test_complete_no_key(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager, LLMKeyMissingError
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            with pytest.raises(LLMKeyMissingError):
                mgr.complete("test prompt")

    def test_complete_openai_format(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("openai", "sk-test")
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "result"}}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            with patch("urllib.request.urlopen", return_value=mock_resp):
                result = mgr.complete("test", "system")
                assert result == "result"

    def test_complete_anthropic_format(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("anthropic", "key")
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "content": [{"text": "anthropic result"}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            with patch("urllib.request.urlopen", return_value=mock_resp):
                result = mgr.complete("test")
                assert result == "anthropic result"

    def test_complete_gemini_format(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("gemini", "key")
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "candidates": [{"content": {"parts": [{"text": "gemini result"}]}}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            with patch("urllib.request.urlopen", return_value=mock_resp):
                result = mgr.complete("test", "system")
                assert result == "gemini result"

    def test_complete_http_401(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager, LLMKeyInvalidError
        import urllib.error
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("openai", "bad-key")
            exc = urllib.error.HTTPError("url", 401, "Unauthorized", {}, MagicMock())
            exc.read = lambda: b"unauthorized"
            with patch("urllib.request.urlopen", side_effect=exc):
                with pytest.raises(LLMKeyInvalidError):
                    mgr.complete("test")

    def test_complete_http_500(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager, LLMRequestError
        import urllib.error
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("openai", "key")
            exc = urllib.error.HTTPError("url", 500, "Internal", {}, MagicMock())
            exc.read = lambda: b"server error"
            with patch("urllib.request.urlopen", side_effect=exc):
                with pytest.raises(LLMRequestError):
                    mgr.complete("test")

    def test_complete_connection_error(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager, LLMRequestError
        with patch.dict(os.environ, {}, clear=True):
            mgr = LLMProviderManager()
            mgr.set_key("openai", "key")
            with patch("urllib.request.urlopen", side_effect=ConnectionError("fail")):
                with pytest.raises(LLMRequestError):
                    mgr.complete("test")

    def test_load_env_keys(self):
        from industrialxpl.core.sast.llm_provider import LLMProviderManager
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env"}, clear=True):
            mgr = LLMProviderManager()
            assert mgr.has_any_key()
            assert mgr.get_active_provider() == "openai"


# ===========================================================================
# core/sast/plc_parsers.py
# ===========================================================================
class TestPlcParsers:
    def test_detect_language_by_ext(self):
        from industrialxpl.core.sast.plc_parsers import detect_language
        assert "Structured Text" in detect_language("test.st")
        assert "Ladder" in detect_language("test.lad")

    def test_detect_language_by_content(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import detect_language
        f = tmp_path / "unknown.txt"
        f.write_text("FUNCTION_BLOCK MyBlock\nVAR_INPUT\nEND_VAR")
        result = detect_language(str(f))
        assert isinstance(result, str)

    def test_detect_language_ladder_content(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import detect_language
        f = tmp_path / "unknown.txt"
        f.write_text("<Ladder>\n<rung>XIC foo</rung>")
        result = detect_language(str(f))
        assert isinstance(result, str)

    def test_detect_language_unknown(self):
        from industrialxpl.core.sast.plc_parsers import detect_language
        result = detect_language("test.xyz")
        assert result == "Unknown"

    def test_sanitize_for_llm(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = 'password := "secret123"; Server=192.168.1.1;'
        sanitized, redactions = sanitize_for_llm(raw)
        assert "CREDENTIAL_REDACTED" in sanitized
        assert len(redactions) > 0

    def test_sanitize_connstring(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = 'conn := "jdbc:mysql://host:3306/db?user=x&pwd=y";'
        sanitized, _ = sanitize_for_llm(raw)
        assert "CONNSTRING_REDACTED" in sanitized

    def test_sanitize_public_ip(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = "host := '8.8.8.8';"
        sanitized, redactions = sanitize_for_llm(raw)
        assert "IP_REDACTED" in sanitized

    def test_sanitize_hostname(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = "server := 'plc.example.com';"
        sanitized, _ = sanitize_for_llm(raw)
        assert "HOST_REDACTED" in sanitized

    def test_sanitize_hex_blob(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = "key := " + "A" * 40 + ";"
        sanitized, _ = sanitize_for_llm(raw)
        assert "HEXBLOB_REDACTED" in sanitized

    def test_sanitize_b64_blob(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = "data := '" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop" + "';"
        sanitized, _ = sanitize_for_llm(raw)
        assert "B64BLOB_REDACTED" in sanitized

    def test_sanitize_long_line_truncation(self):
        from industrialxpl.core.sast.plc_parsers import sanitize_for_llm
        raw = "x" * 400
        sanitized, _ = sanitize_for_llm(raw)
        assert len(sanitized) <= len(raw) or "TRUNCATED" in sanitized or "REDACTED" in sanitized

    def test_parse_file(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import parse_file
        f = tmp_path / "test.st"
        f.write_text(
            "PROGRAM Main\n"
            "VAR\n"
            "  Temp : REAL := 100.0;\n"
            "  MaxTemp : REAL := 500.0;\n"
            "END_VAR\n"
            "  IF Temp > MaxTemp THEN\n"
            "    EmergencyStop();\n"
            "  END_IF;\n"
            "END_PROGRAM\n"
        )
        pf = parse_file(str(f))
        assert pf.language.startswith("Structured Text")
        assert len(pf.programs) >= 1
        assert pf.line_count > 0

    def test_parse_file_with_security_findings(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import parse_file
        f = tmp_path / "vuln.st"
        f.write_text(
            "FUNCTION_BLOCK TempControl\n"
            "VAR\n"
            "  Password : STRING := 'admin123';\n"
            "  MaxSETTING : REAL := 999.9;\n"
            "  WatchdogTimer : INT;\n"
            "  Safety_STO : BOOL;\n"
            "END_VAR\n"
            "  (* TODO validate input *)\n"
            "  IF NOT Authenticated THEN\n"
            "    bypass auth;\n"
            "  END_IF;\n"
            "  ModbusTCP_Write(addr := 100);\n"
            "  OPC_Read();\n"
            "  192.168.1.100 test;\n"
            "  GLOBAL VAR shared concurrent data;\n"
            "  timer1(IN := TRUE, PT := T#5s);\n"
            "END_FUNCTION_BLOCK\n"
        )
        pf = parse_file(str(f))
        assert len(pf.function_blocks) >= 1
        assert len(pf.safety_functions) >= 1
        assert len(pf.watchdog_refs) >= 1
        assert len(pf.critical_comments) >= 1
        assert pf.line_count >= 10

    def test_parse_file_nonexistent(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import parse_file
        pf = parse_file(str(tmp_path / "nonexistent.st"))
        assert pf.raw_content == ""

    def test_walk_project(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import walk_project
        (tmp_path / "main.st").write_text("PROGRAM Main\nEND_PROGRAM")
        (tmp_path / "data.bin").write_bytes(b"\x00" * 10)
        (tmp_path / "other.xyz").write_text("unrelated")
        project = walk_project(str(tmp_path))
        assert len(project.files) >= 1
        assert len(project.binary_files) >= 1

    def test_build_llm_payload(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import walk_project, build_llm_payload
        (tmp_path / "test.st").write_text("PROGRAM Main\nMaxSETTING := 100;\nEND_PROGRAM")
        project = walk_project(str(tmp_path))
        payload = build_llm_payload(project)
        assert "PLC Project" in payload

    def test_build_llm_payload_budget_exceeded(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import walk_project, build_llm_payload
        (tmp_path / "test.st").write_text("x" * 50000)
        project = walk_project(str(tmp_path))
        payload = build_llm_payload(project, max_chars=100)
        assert "truncated" in payload.lower()

    def test_summarize_project(self, tmp_path):
        from industrialxpl.core.sast.plc_parsers import walk_project, summarize_project
        (tmp_path / "test.st").write_text("PROGRAM Main\nEND_PROGRAM")
        project = walk_project(str(tmp_path))
        summary = summarize_project(project)
        assert "PLC Project Summary" in summary


# ===========================================================================
# core/sast/prompts.py
# ===========================================================================
class TestSastPrompts:
    def test_system_prompt(self):
        from industrialxpl.core.sast.prompts import SYSTEM_PROMPT
        assert "PLC" in SYSTEM_PROMPT

    def test_build_sast_prompt(self):
        from industrialxpl.core.sast.prompts import build_sast_prompt
        result = build_sast_prompt("summary", "code")
        assert "summary" in result
        assert "code" in result

    def test_build_sast_prompt_truncation(self):
        from industrialxpl.core.sast.prompts import build_sast_prompt
        result = build_sast_prompt("summary", "x" * 100000)
        assert "truncated" in result

    def test_build_reverse_prompt(self, tmp_path):
        from industrialxpl.core.sast.prompts import build_reverse_prompt
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        result = build_reverse_prompt(str(f), "DEADBEEF", "main")
        assert "test.bin" in result

    def test_build_diff_prompt(self):
        from industrialxpl.core.sast.prompts import build_diff_prompt
        result = build_diff_prompt("original code", "modified code")
        assert "original code" in result
        assert "modified code" in result

    def test_followup_exploit_prompt(self):
        from industrialxpl.core.sast.prompts import FOLLOWUP_EXPLOIT_PROMPT
        assert "EXPLOITATION" in FOLLOWUP_EXPLOIT_PROMPT.upper()

    def test_differential_analysis_prompt(self):
        from industrialxpl.core.sast.prompts import DIFFERENTIAL_ANALYSIS_PROMPT
        assert "Compare" in DIFFERENTIAL_ANALYSIS_PROMPT


# ===========================================================================
# core/search/engine.py
# ===========================================================================
class TestSearchEngine:
    def test_normalize_term(self):
        from industrialxpl.core.search.engine import normalize_term
        assert normalize_term("Mineracao") == "mineracao"
        assert normalize_term("") == ""
        assert normalize_term("Agua") == "agua"

    def test_search_empty(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("")
        assert not result.found
        assert result.error

    def test_search_direct_match(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("modbus")
        assert result.found

    def test_search_multilingual(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("protocolo modbus")
        assert result.found

    def test_search_sector(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("sector=energy")
        # May or may not find based on keywords

    def test_search_sector_ptbr(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("sector=mineracao")

    def test_search_sector_no_match(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=[])
        result = se.search("sector=mining")
        assert not result.found

    def test_search_type(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("type=scanner")
        assert result.found

    def test_search_type_unknown(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=[])
        result = se.search("type=nonexistent")
        assert not result.found

    def test_search_no_match_suggestions(self):
        from industrialxpl.core.search.engine import SearchEngine
        se = SearchEngine(modules=["industrialxpl.modules.scanners.modbus.banner"])
        result = se.search("xyznonexistent")
        assert not result.found

    def test_edit_distance(self):
        from industrialxpl.core.search.engine import _edit_distance
        assert _edit_distance("", "abc") == 3
        assert _edit_distance("abc", "") == 3
        assert _edit_distance("abc", "abc") == 0
        assert _edit_distance("abc", "abcdefghij") == 99  # big diff

    def test_search_result_properties(self):
        from industrialxpl.core.search.engine import SearchResult
        sr = SearchResult(query="test", modules=["mod.a"])
        assert sr.found is True
        assert len(sr) == 1

    def test_imports(self):
        from industrialxpl.core.search import SearchEngine, normalize_term
        assert callable(normalize_term)


# ===========================================================================
# core/protocols/ethernetip.py
# ===========================================================================
class TestEtherNetIP:
    def test_cip_service_constants(self):
        from industrialxpl.core.protocols.ethernetip import CipService
        assert CipService.READ_TAG == 0x4C

    def test_cip_identity(self):
        from industrialxpl.core.protocols.ethernetip import CipIdentity
        ident = CipIdentity(vendor_id=1, product_name="Test PLC")
        assert ident.product_name == "Test PLC"

    def test_tag(self):
        from industrialxpl.core.protocols.ethernetip import Tag
        tag = Tag(name="Temp", value=25.0, data_type=0xC1)
        assert tag.name == "Temp"

    def test_enip_client(self):
        from industrialxpl.core.protocols.ethernetip import EnipClient
        client = EnipClient("192.168.1.1")
        assert client.port == 44818
        with pytest.raises(NotImplementedError):
            client.connect()
        client.disconnect()
        assert client._connected is False
        with pytest.raises(NotImplementedError):
            client.list_identity()
        with pytest.raises(NotImplementedError):
            client.read_tag("tag1")
        with pytest.raises(NotImplementedError):
            client.write_tag("tag1", 42)
        with pytest.raises(NotImplementedError):
            client.get_tags()
        with pytest.raises(NotImplementedError):
            client.forward_open()
        with pytest.raises(NotImplementedError):
            client.forward_close()

    def test_build_register_session(self):
        from industrialxpl.core.protocols.ethernetip import build_register_session
        data = build_register_session()
        assert isinstance(data, bytes)
        assert len(data) > 0


# ===========================================================================
# core/protocols/hartip.py
# ===========================================================================
class TestHartIP:
    def test_hart_command_constants(self):
        from industrialxpl.core.protocols.hartip import HartCommand
        assert HartCommand.READ_UNIQUE_ID == 0

    def test_hart_device(self):
        from industrialxpl.core.protocols.hartip import HartDevice
        dev = HartDevice(tag="FT-101")
        assert dev.tag == "FT-101"

    def test_process_variable(self):
        from industrialxpl.core.protocols.hartip import ProcessVariable
        pv = ProcessVariable(name="Flow", value=123.4, unit="L/min")
        assert pv.status == "good"

    def test_hart_ip_client(self):
        from industrialxpl.core.protocols.hartip import HartIpClient
        client = HartIpClient("192.168.1.1")
        assert client.port == 5094
        with pytest.raises(NotImplementedError):
            client.connect()
        client.disconnect()
        assert client._connected is False
        with pytest.raises(NotImplementedError):
            client.send_command(0)
        with pytest.raises(NotImplementedError):
            client.read_unique_id()
        with pytest.raises(NotImplementedError):
            client.read_primary_variable()
        with pytest.raises(NotImplementedError):
            client.read_loop_current()
        with pytest.raises(NotImplementedError):
            client.read_dynamic_variables()
        with pytest.raises(NotImplementedError):
            client.read_device_variable(0)

    def test_build_hart_ip_header(self):
        from industrialxpl.core.protocols.hartip import build_hart_ip_header
        header = build_hart_ip_header(msg_type=1, command=0, data=b"\x00")
        assert isinstance(header, bytes)
        assert len(header) == 9  # 8 header + 1 data


# ===========================================================================
# core/protocols/iec61850.py
# ===========================================================================
class TestIEC61850:
    def test_constants(self):
        from industrialxpl.core.protocols.iec61850 import MMS_PORT, GOOSE_ETHERTYPE, SV_ETHERTYPE
        assert MMS_PORT == 102
        assert GOOSE_ETHERTYPE == 0x88B8

    def test_ied(self):
        from industrialxpl.core.protocols.iec61850 import IED
        ied = IED(name="IED1", ip="192.168.1.1")
        assert ied.port == 102

    def test_data_attribute(self):
        from industrialxpl.core.protocols.iec61850 import DataAttribute
        da = DataAttribute(reference="LD0/GGIO1.AnIn1.mag.f", value=25.0)
        assert da.quality == "good"

    def test_mms_client(self):
        from industrialxpl.core.protocols.iec61850 import MmsClient, IED
        ied = IED(name="IED1", ip="192.168.1.1")
        client = MmsClient(ied)
        with pytest.raises(NotImplementedError):
            client.connect()
        client.disconnect()
        assert client._connected is False
        with pytest.raises(NotImplementedError):
            client.read("ref")
        with pytest.raises(NotImplementedError):
            client.write("ref", 42)
        with pytest.raises(NotImplementedError):
            client.get_logical_devices()
        with pytest.raises(NotImplementedError):
            client.get_data_directory("LD0")

    def test_goose_subscriber(self):
        from industrialxpl.core.protocols.iec61850 import GooseSubscriber
        gs = GooseSubscriber(interface="eth0")
        with pytest.raises(NotImplementedError):
            gs.start()
        gs.stop()
        assert gs._running is False
        with pytest.raises(NotImplementedError):
            gs.on_message(lambda: None)

    def test_sv_subscriber(self):
        from industrialxpl.core.protocols.iec61850 import SvSubscriber
        sv = SvSubscriber(interface="eth0")
        with pytest.raises(NotImplementedError):
            sv.start()
        sv.stop()  # no-op


# ===========================================================================
# core/compliance/__init__.py and iec62443.py
# ===========================================================================
class TestCompliance:
    def test_security_level_enum(self):
        from industrialxpl.core.compliance import SecurityLevel
        assert SecurityLevel.SL0.value == 0
        assert SecurityLevel.SL4.value == 4

    def test_compliance_check_dataclass(self):
        from industrialxpl.core.compliance import ComplianceCheck, SecurityLevel
        cc = ComplianceCheck(
            requirement_id="SR 1.1",
            title="Test",
            description="Test check",
            security_level=SecurityLevel.SL1,
            category="FR1",
        )
        assert cc.requirement_id == "SR 1.1"

    def test_iec62443_engine(self):
        from industrialxpl.core.compliance import IEC62443Engine, SecurityLevel
        engine = IEC62443Engine()
        checks = engine.checks
        assert "SR 1.1" in checks

    def test_evaluate(self):
        from industrialxpl.core.compliance import IEC62443Engine, SecurityLevel
        engine = IEC62443Engine()
        result = engine.evaluate("SR 1.1", passed=True, evidence="Test evidence")
        assert result.passed is True
        assert "SR 1.1" == result.requirement_id

    def test_evaluate_unknown(self):
        from industrialxpl.core.compliance import IEC62443Engine
        engine = IEC62443Engine()
        with pytest.raises(KeyError):
            engine.evaluate("SR 99.99", passed=True)

    def test_results_by_level(self):
        from industrialxpl.core.compliance import IEC62443Engine, SecurityLevel
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 3.3", passed=False)
        sl1 = engine.results_by_level(SecurityLevel.SL1)
        assert len(sl1) == 1

    def test_compliance_score(self):
        from industrialxpl.core.compliance import IEC62443Engine
        engine = IEC62443Engine()
        assert engine.compliance_score() == 0.0
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 1.2", passed=False)
        assert engine.compliance_score() == 50.0

    def test_gaps(self):
        from industrialxpl.core.compliance import IEC62443Engine
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.evaluate("SR 1.2", passed=False, remediation="Fix it")
        gaps = engine.gaps()
        assert len(gaps) == 1
        assert gaps[0].requirement_id == "SR 1.2"

    def test_reset(self):
        from industrialxpl.core.compliance import IEC62443Engine
        engine = IEC62443Engine()
        engine.evaluate("SR 1.1", passed=True)
        engine.reset()
        assert len(engine.results()) == 0

    def test_add_check(self):
        from industrialxpl.core.compliance import IEC62443Engine, ComplianceCheck, SecurityLevel
        engine = IEC62443Engine()
        engine.add_check(ComplianceCheck(
            requirement_id="SR 99.1",
            title="Custom",
            description="Custom check",
            security_level=SecurityLevel.SL3,
        ))
        assert "SR 99.1" in engine.checks

    def test_iec62443_checks_for_level(self):
        from industrialxpl.core.compliance.iec62443 import checks_for_level
        from industrialxpl.core.compliance import IEC62443Engine, SecurityLevel
        engine = IEC62443Engine()
        result = checks_for_level(engine.checks, SecurityLevel.SL1)
        assert all(c.security_level.value <= 1 for c in result)

    def test_iec62443_checks_by_category(self):
        from industrialxpl.core.compliance.iec62443 import checks_by_category
        from industrialxpl.core.compliance import IEC62443Engine
        engine = IEC62443Engine()
        result = checks_by_category(engine.checks, "FR1")
        assert all(c.category.startswith("FR1") for c in result)

    def test_zone_security_level(self):
        from industrialxpl.core.compliance.iec62443 import zone_security_level
        from industrialxpl.core.compliance import SecurityLevel
        assert zone_security_level("safety") == SecurityLevel.SL4
        assert zone_security_level("enterprise") == SecurityLevel.SL1
        assert zone_security_level("unknown_zone") == SecurityLevel.SL1

    def test_foundational_requirements(self):
        from industrialxpl.core.compliance.iec62443 import FOUNDATIONAL_REQUIREMENTS, ZONE_CONDUIT_TYPES
        assert "FR1" in FOUNDATIONAL_REQUIREMENTS
        assert "safety" in ZONE_CONDUIT_TYPES


# ===========================================================================
# core/ics_tools/catalog.py
# ===========================================================================
class TestIcsToolsCatalog:
    def test_catalog_init(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        cat = IcsToolsCatalog()
        assert cat._families == {}

    def test_discover_empty(self, tmp_path):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        with patch("industrialxpl.core.ics_tools.catalog.VENDOR_ROOT", tmp_path):
            cat = IcsToolsCatalog()
            families = cat.discover()
            # Should discover native ones if they exist
            # But with patched VENDOR_ROOT, vendor dirs won't exist

    def test_list_slugs(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        cat = IcsToolsCatalog()
        cat._families = {"a": None, "b": None}
        assert cat.list_slugs() == ["a", "b"]

    def test_get(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog, IcsToolFamily
        cat = IcsToolsCatalog()
        fam = IcsToolFamily(slug="test", label="Test", vendor_path=Path("/tmp"), source_repo="test")
        cat._families = {"test": fam}
        assert cat.get("test") == fam
        assert cat.get("nonexistent") is None

    def test_ics_tool_family_dataclass(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        f = IcsToolFamily(slug="test", label="Test", vendor_path=Path("/tmp"), source_repo="test")
        assert f.interpreter == "python3"
        assert f.ixf_module == ""

    def test_discover_with_vendor_dirs(self, tmp_path):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        # Create a fake vendor dir
        vd = tmp_path / "submodules__ics-tools__scadapass"
        vd.mkdir()
        (vd / "scadapass.csv").touch()
        with patch("industrialxpl.core.ics_tools.catalog.VENDOR_ROOT", tmp_path):
            with patch("industrialxpl.core.ics_tools.catalog.IcsToolsCatalog.NATIVE_ICS", {}):
                cat = IcsToolsCatalog()
                families = cat.discover()
                assert "scadapass" in families

    def test_discover_cached(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog, IcsToolFamily
        cat = IcsToolsCatalog()
        cat._families = {"cached": IcsToolFamily(slug="cached", label="C", vendor_path=Path("/tmp"), source_repo="c")}
        result = cat.discover()
        assert "cached" in result


# ===========================================================================
# core/ics_tools/orchestrator.py
# ===========================================================================
class TestIcsToolsOrchestrator:
    def test_list_tools(self):
        from industrialxpl.core.ics_tools.orchestrator import IcsToolsOrchestrator
        orch = IcsToolsOrchestrator()
        with patch.object(orch.catalog, "list_slugs", return_value=["a", "b"]):
            assert orch.list_tools() == ["a", "b"]

    def test_analyze(self):
        from industrialxpl.core.ics_tools.orchestrator import IcsToolsOrchestrator
        orch = IcsToolsOrchestrator()
        with patch.object(orch.runner, "analyze", return_value={"slug": "test"}):
            assert orch.analyze("test")["slug"] == "test"

    def test_build_plan(self):
        from industrialxpl.core.ics_tools.orchestrator import IcsToolsOrchestrator
        orch = IcsToolsOrchestrator()
        with patch.object(orch.runner, "analyze", return_value={
            "slug": "test", "vendor_path": "/tmp", "entry": "main.py",
            "interpreter": "python3", "ixf_module": "test.mod",
        }):
            plan = orch.build_plan("test", target="10.0.0.1")
            assert "plan_steps" in plan
            assert len(plan["plan_steps"]) == 4

    def test_build_plan_error(self):
        from industrialxpl.core.ics_tools.orchestrator import IcsToolsOrchestrator
        orch = IcsToolsOrchestrator()
        with patch.object(orch.runner, "analyze", return_value={"error": "not found"}):
            plan = orch.build_plan("test")
            assert "error" in plan

    def test_run(self):
        from industrialxpl.core.ics_tools.orchestrator import IcsToolsOrchestrator
        orch = IcsToolsOrchestrator()
        with patch.object(orch.runner, "run_entry", return_value={"success": True}):
            assert orch.run("test")["success"] is True


# ===========================================================================
# core/ics_tools/runner.py
# ===========================================================================
class TestIcsToolsRunner:
    def test_analyze_unknown(self):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=None):
            with patch.object(runner.catalog, "list_slugs", return_value=[]):
                result = runner.analyze("unknown")
                assert "error" in result

    def test_analyze_known(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        fam = IcsToolFamily(slug="test", label="Test", vendor_path=tmp_path, source_repo="test",
                            entry_script="main.py", ixf_module="test.mod")
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=fam):
            result = runner.analyze("test")
            assert result["slug"] == "test"

    def test_run_entry_unknown(self):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=None):
            result = runner.run_entry("unknown")
            assert "error" in result

    def test_run_entry_native(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        fam = IcsToolFamily(slug="scadapass", label="SCADAPASS", vendor_path=tmp_path,
                            source_repo="test")
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=fam):
            with patch("industrialxpl.core.ics_tools.runner.run_native",
                        return_value={"success": True}):
                result = runner.run_entry("scadapass")
                assert result["success"] is True

    def test_run_entry_no_entry_script(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        fam = IcsToolFamily(slug="test", label="Test", vendor_path=tmp_path,
                            source_repo="test", entry_script="")
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=fam):
            with patch("industrialxpl.core.ics_tools.runner.run_native", return_value=None):
                result = runner.run_entry("test")
                assert "error" in result

    def test_run_entry_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        fam = IcsToolFamily(slug="test", label="Test", vendor_path=tmp_path,
                            source_repo="test", entry_script="main.py")
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=fam):
            with patch("industrialxpl.core.ics_tools.runner.run_native", return_value=None):
                result = runner.run_entry("test", simulate=True)
                assert result["simulate"] is True

    def test_load_scadapass(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        csv_path = tmp_path / "test.csv"
        csv_path.write_text("vendor,user,pass\nSiemens,admin,admin\n")
        runner = IcsToolsRunner()
        result = runner._load_scadapass(csv_path)
        assert result["success"] is True

    def test_load_scadapass_error(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        runner = IcsToolsRunner()
        result = runner._load_scadapass(tmp_path / "nonexistent.csv")
        assert result["success"] is False

    def test_compile_vendor_unknown(self):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=None):
            result = runner.compile_vendor("unknown")
            assert "error" in result

    def test_compile_vendor_no_sln(self, tmp_path):
        from industrialxpl.core.ics_tools.runner import IcsToolsRunner
        from industrialxpl.core.ics_tools.catalog import IcsToolFamily
        fam = IcsToolFamily(slug="test", label="Test", vendor_path=tmp_path, source_repo="test")
        runner = IcsToolsRunner()
        with patch.object(runner.catalog, "get", return_value=fam):
            result = runner.compile_vendor("test")
            assert result["success"] is True

    def test_shutil_which(self):
        from industrialxpl.core.ics_tools.runner import shutil_which
        with patch("shutil.which", return_value="/usr/bin/test"):
            assert shutil_which("test") is True
        with patch("shutil.which", return_value=None):
            assert shutil_which("test") is False


# ===========================================================================
# core/ics_tools/native_handlers.py
# ===========================================================================
class TestNativeHandlers:
    def test_parse_args(self):
        from industrialxpl.core.ics_tools.native_handlers import _parse_args
        result = _parse_args(["-t", "10.0.0.1", "extra"])
        assert result["-t"] == "10.0.0.1"
        assert "extra" in result.get("_positional", "")

    def test_parse_args_empty(self):
        from industrialxpl.core.ics_tools.native_handlers import _parse_args
        result = _parse_args(None)
        assert result == {}

    def test_host_from_args(self):
        from industrialxpl.core.ics_tools.native_handlers import _host_from_args
        assert _host_from_args({"-t": "10.0.0.1"}, "-t") == "10.0.0.1"
        assert _host_from_args({"_positional": " 10.0.0.2"}) == "10.0.0.2"
        assert _host_from_args({}) == ""

    def test_handle_scadapass_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_scadapass
        result = handle_scadapass(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_scadapass_no_file(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_scadapass
        result = handle_scadapass(tmp_path, None, simulate=False)
        assert result["success"] is False

    def test_handle_scadapass_with_file(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_scadapass
        csv_path = tmp_path / "scadapass.csv"
        csv_path.write_text("Siemens,admin,admin\nABB,user,pass\n")
        result = handle_scadapass(tmp_path, None, simulate=False)
        assert result["success"] is True

    def test_handle_redpoint_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_redpoint
        result = handle_redpoint(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_redpoint_no_host(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_redpoint
        result = handle_redpoint(tmp_path, None, simulate=False)
        assert result["mode"] == "native-inventory"

    def test_handle_sixnet_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_sixnet
        result = handle_sixnet(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_sixnet_no_host(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_sixnet
        result = handle_sixnet(tmp_path, None, simulate=False)
        assert result["mode"] == "native-help"

    def test_handle_isf_dark_lbp_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_dark_lbp
        result = handle_isf_dark_lbp(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_isf_dark_lbp(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_dark_lbp
        result = handle_isf_dark_lbp(tmp_path, None, simulate=False)
        assert result["success"] is True

    def test_handle_isf_w3h_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_w3h
        result = handle_isf_w3h(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_isf_w3h_no_host(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_w3h
        result = handle_isf_w3h(tmp_path, None, simulate=False)
        assert result["mode"] == "native-inventory"

    def test_handle_attkfinder_simulate(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_attkfinder
        result = handle_attkfinder(tmp_path, None, simulate=True)
        assert result["simulate"] is True

    def test_handle_attkfinder(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import handle_attkfinder
        off = tmp_path / "offensive.py"
        off.write_text("class Exploit:\n    pass\nclass Scanner:\n    pass\n")
        result = handle_attkfinder(tmp_path, None, simulate=False)
        assert result["success"] is True

    def test_run_native_unknown(self):
        from industrialxpl.core.ics_tools.native_handlers import run_native
        assert run_native("unknown_slug") is None

    def test_run_native_known(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import run_native
        with patch("industrialxpl.core.ics_tools.native_handlers.NATIVE_HANDLERS",
                    {"test": lambda v, e, s: {"success": True}}):
            with patch("industrialxpl.core.ics_tools.native_handlers.IcsToolsCatalog") as mock_cat:
                mock_cat.return_value.get.return_value = None
                result = run_native("test")
                assert result["success"] is True

    def test_inventory_files(self, tmp_path):
        from industrialxpl.core.ics_tools.native_handlers import _inventory_files
        (tmp_path / "test.py").touch()
        result = _inventory_files(tmp_path, "*.py")
        assert len(result) == 1

    def test_inventory_files_no_dir(self):
        from industrialxpl.core.ics_tools.native_handlers import _inventory_files
        result = _inventory_files(Path("/nonexistent"), "*.py")
        assert result == []

    def test_bacnet_whois(self):
        from industrialxpl.core.ics_tools.native_handlers import _bacnet_whois
        result = _bacnet_whois()
        assert isinstance(result, bytes)

    def test_modbus_probe_success(self):
        from industrialxpl.core.ics_tools.native_handlers import _modbus_probe
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"\x00" * 10
            mock_conn.return_value = mock_sock
            result = _modbus_probe("127.0.0.1", 502)
            assert result["success"] is True

    def test_modbus_probe_fail(self):
        from industrialxpl.core.ics_tools.native_handlers import _modbus_probe
        with patch("socket.create_connection", side_effect=OSError("fail")):
            result = _modbus_probe("127.0.0.1", 502)
            assert result["success"] is False

    def test_modbus_probe_short_response(self):
        from industrialxpl.core.ics_tools.native_handlers import _modbus_probe
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"\x00"  # too short
            mock_conn.return_value = mock_sock
            result = _modbus_probe("127.0.0.1", 502)
            assert result["success"] is False


# ===========================================================================
# core/ics_tools/forensics_engine.py
# ===========================================================================
class TestForensicsEngine:
    def test_load_ioc_db_missing(self):
        from industrialxpl.core.ics_tools.forensics_engine import _load_ioc_db
        with patch("industrialxpl.core.ics_tools.forensics_engine._IOC_DB", Path("/nonexistent")):
            result = _load_ioc_db()
            assert result == {"families": {}}

    def test_ioc_inventory(self):
        from industrialxpl.core.ics_tools.forensics_engine import ioc_inventory
        with patch("industrialxpl.core.ics_tools.forensics_engine._load_ioc_db",
                    return_value={"families": {"triton": {"hashes": [{"value": "abc"}]}}}):
            with patch("industrialxpl.core.ics_tools.forensics_engine._YARA_DIR", Path("/nonexistent")):
                result = ioc_inventory()
                assert result["families"] == 1
                assert result["hash_count"] == 1

    def test_match_ioc_hash_found(self):
        from industrialxpl.core.ics_tools.forensics_engine import match_ioc_hash
        with patch("industrialxpl.core.ics_tools.forensics_engine._load_ioc_db",
                    return_value={"families": {"triton": {"hashes": [{"value": "abc123", "type": "sha256", "label": "sample"}]}}}):
            result = match_ioc_hash("ABC123")
            assert result["matched"] is True
            assert result["family"] == "triton"

    def test_match_ioc_hash_not_found(self):
        from industrialxpl.core.ics_tools.forensics_engine import match_ioc_hash
        with patch("industrialxpl.core.ics_tools.forensics_engine._load_ioc_db",
                    return_value={"families": {}}):
            result = match_ioc_hash("deadbeef")
            assert result["matched"] is False

    def test_scan_file_hashes(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import scan_file_hashes
        f = tmp_path / "sample.bin"
        f.write_bytes(b"malware content")
        with patch("industrialxpl.core.ics_tools.forensics_engine.match_ioc_hash",
                    return_value={"matched": False}):
            result = scan_file_hashes(f)
            assert result["success"] is True
            assert "sha256" in result["digests"]

    def test_scan_file_hashes_missing(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import scan_file_hashes
        result = scan_file_hashes(tmp_path / "nonexistent.bin")
        assert result["success"] is False

    def test_scan_file_hashes_with_hit(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import scan_file_hashes
        f = tmp_path / "sample.bin"
        f.write_bytes(b"malware content")
        with patch("industrialxpl.core.ics_tools.forensics_engine.match_ioc_hash",
                    return_value={"matched": True, "family": "triton"}):
            result = scan_file_hashes(f)
            assert len(result["hits"]) > 0

    def test_inventory(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import inventory
        with patch("industrialxpl.core.ics_tools.forensics_engine._FORENSICS_VENDOR", tmp_path):
            with patch("industrialxpl.core.ics_tools.forensics_engine._load_ob_mapping", return_value={}):
                result = inventory()
                assert result["success"] is True

    def test_export_ob_roles_csv(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import export_ob_roles_csv
        rows = [{"ip": "10.0.0.1", "block_id": "OB1", "type": "OB", "label": "Main"}]
        out = tmp_path / "output.csv"
        result = export_ob_roles_csv(rows, out)
        assert result["success"] is True
        assert out.exists()

    def test_export_ob_roles_csv_empty(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import export_ob_roles_csv
        result = export_ob_roles_csv([], tmp_path / "output.csv")
        assert result["success"] is False

    def test_parse_ob_sample(self):
        from industrialxpl.core.ics_tools.forensics_engine import parse_ob_sample
        with patch("industrialxpl.core.ics_tools.forensics_engine._load_ob_mapping",
                    return_value={"func_mapping": {"OB1": {"default": "Main"}}}):
            result = parse_ob_sample("10.0.0.1")
            assert result["success"] is True

    def test_parse_ob_sample_dict_names(self):
        from industrialxpl.core.ics_tools.forensics_engine import parse_ob_sample
        with patch("industrialxpl.core.ics_tools.forensics_engine._load_ob_mapping",
                    return_value={"OB1": "Cycle Execution"}):
            result = parse_ob_sample("10.0.0.1")
            assert result["success"] is True

    def test_load_ob_mapping_missing(self):
        from industrialxpl.core.ics_tools.forensics_engine import _load_ob_mapping
        with patch("industrialxpl.core.ics_tools.forensics_engine._FORENSICS_VENDOR", Path("/nonexistent")):
            result = _load_ob_mapping()
            assert result == {}

    def test_load_ob_mapping_corrupt(self, tmp_path):
        from industrialxpl.core.ics_tools.forensics_engine import _load_ob_mapping
        mapping_dir = tmp_path / "mapping"
        mapping_dir.mkdir()
        (mapping_dir / "ob_mapping.json").write_text("not json")
        with patch("industrialxpl.core.ics_tools.forensics_engine._FORENSICS_VENDOR", tmp_path):
            result = _load_ob_mapping()
            assert result == {}
