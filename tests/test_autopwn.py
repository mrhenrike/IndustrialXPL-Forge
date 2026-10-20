"""Tests for AutoPwn engine (base, modbus, dnp3, s7comm, ics)."""

import pytest
from unittest.mock import patch, MagicMock

from industrialxpl.modules.autopwn.base import AutoPwnReport, SegmentAutoPwn
from industrialxpl.modules.autopwn.modbus import ModbusAutoPwn
from industrialxpl.modules.autopwn.dnp3 import Dnp3AutoPwn
from industrialxpl.modules.autopwn.s7comm import S7commAutoPwn
from industrialxpl.modules.autopwn.ics import IcsAutoPwn


class TestAutoPwnReport:
    def test_defaults(self):
        r = AutoPwnReport(segment="modbus", targets=["10.0.0.1"])
        assert r.segment == "modbus"
        assert r.targets == ["10.0.0.1"]
        assert r.modules_run == 0
        assert r.modules_vulnerable == 0
        assert r.results == []
        assert r.elapsed_s == 0.0

    def test_summary_format(self):
        r = AutoPwnReport(segment="dnp3", targets=["10.0.0.1"])
        r.modules_run = 5
        r.modules_vulnerable = 2
        s = r.summary()
        assert "DNP3" in s
        assert "5 modules" in s
        assert "2 vulnerable" in s

    def test_summary_with_results(self):
        r = AutoPwnReport(segment="s7comm", targets=["10.0.0.1"])
        r.results = [
            ("mod.a", "10.0.0.1", "vulnerable"),
            ("mod.b", "10.0.0.1", "not_vulnerable"),
        ]
        r.modules_run = 2
        r.modules_vulnerable = 1
        s = r.summary()
        assert "S7COMM" in s


class TestSegmentAutoPwn:
    def test_init_single_target(self):
        ap = SegmentAutoPwn("modbus", "10.0.0.1")
        assert ap.segment == "modbus"
        assert ap.targets == ["10.0.0.1"]
        assert ap.check_only is True
        assert ap.verbose is True

    def test_init_multiple_targets(self):
        ap = SegmentAutoPwn("dnp3", ["10.0.0.1", "10.0.0.2"])
        assert len(ap.targets) == 2

    def test_init_lowercase_segment(self):
        ap = SegmentAutoPwn("MODBUS", "10.0.0.1")
        assert ap.segment == "modbus"

    def test_init_check_only_false(self):
        ap = SegmentAutoPwn("modbus", "10.0.0.1", check_only=False)
        assert ap.check_only is False

    def test_get_modules_returns_list(self):
        ap = SegmentAutoPwn("modbus", "10.0.0.1")
        mods = ap._get_modules()
        assert isinstance(mods, list)

    def test_run_no_modules(self):
        ap = SegmentAutoPwn("modbus", "10.0.0.1", verbose=False)
        with patch.object(ap, "_get_modules", return_value=[]):
            report = ap.run()
        assert isinstance(report, AutoPwnReport)
        assert report.modules_run == 0
        assert report.elapsed_s >= 0

    def test_run_with_targets_iterated(self):
        """Verify run iterates over all targets even with no modules."""
        ap = SegmentAutoPwn("modbus", ["10.0.0.1", "10.0.0.2"], verbose=False)
        with patch.object(ap, "_get_modules", return_value=[]):
            report = ap.run()
        assert report.targets == ["10.0.0.1", "10.0.0.2"]
        assert report.modules_run == 0

    def test_run_error_handling(self):
        mock_rec = MagicMock()
        mock_rec.path = "industrialxpl.modules.exploits.broken"

        ap = SegmentAutoPwn("modbus", "10.0.0.1", verbose=False)
        with patch.object(ap, "_get_modules", return_value=[mock_rec]), \
             patch("importlib.import_module", side_effect=ImportError("no module")):
            report = ap.run()
        assert report.modules_run == 1
        assert report.results[0][2] == "error"


class TestModbusAutoPwn:
    def test_init(self):
        ap = ModbusAutoPwn("10.0.0.1")
        assert ap.segment == "modbus"
        assert ap.targets == ["10.0.0.1"]

    def test_inherits_segment_autopwn(self):
        assert issubclass(ModbusAutoPwn, SegmentAutoPwn)


class TestDnp3AutoPwn:
    def test_init(self):
        ap = Dnp3AutoPwn(["10.0.0.1", "10.0.0.2"])
        assert ap.segment == "dnp3"
        assert len(ap.targets) == 2

    def test_inherits_segment_autopwn(self):
        assert issubclass(Dnp3AutoPwn, SegmentAutoPwn)


class TestS7commAutoPwn:
    def test_init(self):
        ap = S7commAutoPwn("192.168.1.1")
        assert ap.segment == "s7comm"

    def test_inherits_segment_autopwn(self):
        assert issubclass(S7commAutoPwn, SegmentAutoPwn)


class TestIcsAutoPwn:
    def test_init(self):
        ap = IcsAutoPwn("10.0.0.1")
        assert ap.segment == "ics"

    def test_inherits_segment_autopwn(self):
        assert issubclass(IcsAutoPwn, SegmentAutoPwn)

    def test_run_empty(self):
        ap = IcsAutoPwn("10.0.0.1", verbose=False)
        with patch.object(ap, "_get_modules", return_value=[]):
            report = ap.run()
        assert report.segment == "ics"
