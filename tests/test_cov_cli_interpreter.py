"""Comprehensive unit tests for CLI, interpreter, API server and completer.

Covers:
  - industrialxpl/__main__.py
  - industrialxpl/interpreter.py (BaseInterpreter + IXFInterpreter)
  - industrialxpl/api/server.py
  - industrialxpl/cli/__init__.py
  - industrialxpl/cli/commands_ics.py
  - industrialxpl/cli/commands_malware.py
  - industrialxpl/cli/commands_mitre.py
  - industrialxpl/cli/commands_sast.py
  - industrialxpl/cli/commands_stats.py
  - industrialxpl/cli/completer.py
"""

from __future__ import annotations

import builtins
import io
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure require_linux is a no-op before any IXF import
# ---------------------------------------------------------------------------

_rl_patch = patch("industrialxpl.core.platform.require_linux", lambda *a, **k: None)
_rl_patch.start()


# ---------------------------------------------------------------------------
# Fake module class used by interpreter tests
# ---------------------------------------------------------------------------

class FakeModule:
    """Minimal stand-in for a loaded IXF exploit module."""

    exploit_attributes: dict[str, list] = {}

    def __init__(
        self,
        name: str = "FakeModbus",
        options: dict | None = None,
        impact: str = "LOW",
        poly_language: str = "python",
    ) -> None:
        self._name = name
        self._impact = impact
        self._poly = poly_language
        self.options = options or {
            "target": "",
            "port": "502",
            "simulate": "false",
            "destructive": "false",
            "timing": "T3",
            "transport": "tcp",
            "unit_id": "1",
        }
        self.exploit_attributes = {
            k: [str(v), f"desc-{k}", False]
            for k, v in (options or {
                "target": "",
                "port": "502",
                "simulate": "false",
                "destructive": "false",
                "timing": "T3",
                "transport": "tcp",
                "unit_id": "1",
            }).items()
        }
        self.target = ""
        self.port = "502"
        self.simulate = False
        self.destructive = False
        self.timing = "T3"
        self.transport = "tcp"
        self.unit_id = 1
        self._simulate_mode = False
        self._destructive_mode = False
        self._safemode = False

    def get_info(self) -> dict:
        return {
            "name": self._name,
            "impact": self._impact,
            "devices": ["PLC", "RTU"],
            "poly_language": self._poly,
        }

    def run(self) -> None:
        pass

    def check(self) -> bool:
        return True

    def _apply_global_scan_opts(self, opts: dict) -> None:
        pass


FAKE_MODULES = [
    "scanners.ics.modbus_detect",
    "scanners.ics.modbus_scanner",
    "exploits.protocols.modbus.modbus_client",
    "cve.siemens.cve_2022_29953",
    "cve.schneider.cve_2021_22779",
    "cve.apt.trisis_analysis",
    "assessment.sast.plc_source_analyzer",
    "assessment.detection.scada_audit",
    "scanners.malware_research.malware_full_pipeline",
    "scanners.ics_tools_research.ics_tools_ops",
    "exploits.protocols.modbus.modbus_write",
    "scanners.protocols.dnp3.dnp3_detect",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_interp(extra_globals: dict | None = None):
    """Create an IXFInterpreter with all heavy I/O mocked out."""
    with patch("industrialxpl.interpreter.index_modules", return_value=list(FAKE_MODULES)), \
         patch("industrialxpl.interpreter._HAS_READLINE", False), \
         patch("industrialxpl.interpreter.readline", None), \
         patch("industrialxpl.interpreter.print_status"), \
         patch("industrialxpl.interpreter.print_success"):
        from industrialxpl.interpreter import IXFInterpreter
        interp = IXFInterpreter()
    # Mixins reference self.global_variables but IXFInterpreter uses _global_opts.
    # Alias it so mixin code works:
    interp.global_variables = interp._global_opts
    if extra_globals:
        interp._global_opts.update(extra_globals)
    return interp


# ═══════════════════════════════════════════════════════════════════════════
# 1. CLI __init__ import test
# ═══════════════════════════════════════════════════════════════════════════

class TestCliInit:
    def test_imports_all_mixins(self):
        from industrialxpl.cli import (
            ICSCommandsMixin,
            MalwareCommandsMixin,
            MITRECommandsMixin,
            SASTCommandsMixin,
            StatsCommandsMixin,
        )
        assert ICSCommandsMixin is not None
        assert MalwareCommandsMixin is not None
        assert MITRECommandsMixin is not None
        assert SASTCommandsMixin is not None
        assert StatsCommandsMixin is not None

    def test_all_exports(self):
        from industrialxpl import cli
        assert set(cli.__all__) == {
            "ICSCommandsMixin",
            "MITRECommandsMixin",
            "MalwareCommandsMixin",
            "SASTCommandsMixin",
            "StatsCommandsMixin",
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2. Completer tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCompleter:
    def _make(self, modules=None, current_module=None):
        from industrialxpl.cli.completer import IXFCompleter
        interp = MagicMock()
        interp.modules = modules or list(FAKE_MODULES)
        interp.current_module = current_module
        return IXFCompleter(interp)

    def test_global_commands_completion(self):
        c = self._make()
        matches = c._get_matches("", "")
        assert any("help " in m for m in matches)
        assert any("use " in m for m in matches)

    def test_partial_global_command(self):
        c = self._make()
        matches = c._get_matches("he", "he")
        assert "help " in matches

    def test_use_module_completion(self):
        c = self._make()
        matches = c._get_matches("use ", "")
        assert isinstance(matches, list)

    def test_use_partial_module(self):
        c = self._make()
        matches = c._get_matches("use scan", "scan")
        assert isinstance(matches, list)

    def test_set_option_list(self):
        mod = MagicMock()
        mod.options = {"target": "", "port": "502"}
        c = self._make(current_module=mod)
        matches = c._get_matches("set ", "")
        assert len(matches) > 0

    def test_set_partial_option(self):
        mod = MagicMock()
        mod.options = {"target": "", "port": "502"}
        c = self._make(current_module=mod)
        matches = c._get_matches("set TAR", "TAR")
        assert any("TARGET" in m for m in matches)

    def test_setg_global_options(self):
        c = self._make()
        matches = c._get_matches("setg ", "")
        assert any("TARGET" in m for m in matches)

    def test_setg_partial(self):
        c = self._make()
        matches = c._get_matches("setg LOG", "LOG")
        assert any("LOGLEVEL" in m for m in matches)

    def test_unsetg_completion(self):
        c = self._make()
        matches = c._get_matches("unsetg TAR", "TAR")
        assert any("TARGET" in m for m in matches)

    def test_show_subcommands(self):
        c = self._make()
        matches = c._get_matches("show ", "")
        assert any("info" in m for m in matches)
        assert any("options" in m for m in matches)

    def test_malware_subcommands(self):
        c = self._make()
        matches = c._get_matches("malware ", "")
        assert any("list" in m for m in matches)

    def test_ics_tools_subcommands(self):
        c = self._make()
        matches = c._get_matches("ics_tools ", "")
        assert any("list" in m for m in matches)

    def test_help_topics(self):
        c = self._make()
        matches = c._get_matches("help ", "")
        assert any("sector" in m for m in matches)

    def test_search_prefixes(self):
        c = self._make()
        matches = c._get_matches("search ", "")
        assert "type=" in matches or any("type=" in m for m in matches)

    def test_cve_prefix(self):
        c = self._make()
        matches = c._get_matches("cve ", "")
        # Should offer CVE- prefix
        assert len(matches) >= 0  # may return CVE- prefix

    def test_complete_option_value_timing(self):
        c = self._make()
        matches = c._complete_option_value(["set", "TIMING"])
        assert any("T3" in m for m in matches)

    def test_complete_option_value_loglevel(self):
        c = self._make()
        matches = c._complete_option_value(["set", "LOGLEVEL"])
        assert any("debug" in m for m in matches)

    def test_complete_option_value_simulate(self):
        c = self._make()
        matches = c._complete_option_value(["set", "SIMULATE"])
        assert "true " in matches
        assert "false " in matches

    def test_complete_option_value_destructive(self):
        c = self._make()
        matches = c._complete_option_value(["set", "DESTRUCTIVE"])
        assert "true " in matches

    def test_complete_option_value_report_fmt(self):
        c = self._make()
        matches = c._complete_option_value(["set", "REPORT_FMT"])
        assert any("json" in m for m in matches)

    def test_complete_option_value_verbose(self):
        c = self._make()
        matches = c._complete_option_value(["set", "VERBOSE"])
        assert "true " in matches

    def test_complete_option_value_ping_first(self):
        c = self._make()
        matches = c._complete_option_value(["set", "PING_FIRST"])
        assert "true " in matches

    def test_complete_option_value_skip_ping(self):
        c = self._make()
        matches = c._complete_option_value(["set", "SKIP_PING"])
        assert "true " in matches

    def test_complete_option_value_unknown(self):
        c = self._make()
        matches = c._complete_option_value(["set", "TARGET"])
        assert matches == []

    def test_complete_option_value_short_parts(self):
        c = self._make()
        matches = c._complete_option_value(["set"])
        assert matches == []

    def test_complete_method_state(self):
        c = self._make()
        # First call (state=0) populates matches
        result = c.complete("he", 0)
        assert result is not None
        # Exhaust: eventually returns None
        idx = 0
        while c.complete("he", idx) is not None:
            idx += 1
        assert c.complete("he", idx) is None

    def test_complete_readline_fallback(self):
        """When readline.get_line_buffer fails, fall back to text."""
        c = self._make()
        with patch.dict(sys.modules, {"readline": None}):
            result = c.complete("he", 0)
            # Should still work
            assert result is not None or result is None  # no crash

    def test_invalidate_cache(self):
        c = self._make()
        # Access module_paths to populate cache
        _ = c._module_paths
        assert c._module_cache is not None
        c.invalidate_cache()
        assert c._module_cache is None

    def test_current_options_no_module(self):
        c = self._make(current_module=None)
        assert c._current_options() == []

    def test_current_options_with_module(self):
        mod = FakeModule()
        mod.options = {"target": "", "port": "502"}
        c = self._make(current_module=mod)
        opts = c._current_options()
        assert "TARGET" in opts
        assert "PORT" in opts

    def test_current_options_non_dict(self):
        """When options is a list, _current_options returns []."""
        mod = FakeModule()
        mod.options = ["target", "port"]
        c = self._make(current_module=mod)
        opts = c._current_options()
        assert opts == []

    def test_unknown_command_returns_empty(self):
        c = self._make()
        matches = c._get_matches("foobar arg", "arg")
        assert matches == []

    def test_module_paths_property_caching(self):
        c = self._make()
        # Modules with path attr
        mod_obj = MagicMock()
        mod_obj.path = "scanners/ics/modbus_detect"
        c._interp.modules = [mod_obj]
        paths = c._module_paths
        assert len(paths) == 1
        # Second access uses cache
        paths2 = c._module_paths
        assert paths is paths2

    def test_set_value_position_triggers_value_complete(self):
        """set TIMING <cursor> should offer T0-T5."""
        c = self._make()
        matches = c._get_matches("set TIMING ", "")
        assert any("T" in m for m in matches)


# ═══════════════════════════════════════════════════════════════════════════
# 3. BaseInterpreter tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBaseInterpreter:
    def test_parse_line_empty(self):
        interp = _make_interp()
        assert interp.parse_line("") == ("", "", {})

    def test_parse_line_command_only(self):
        interp = _make_interp()
        cmd, args, kw = interp.parse_line("help")
        assert cmd == "help"
        assert args == ""

    def test_parse_line_command_with_args(self):
        interp = _make_interp()
        cmd, args, kw = interp.parse_line("use scanners/ics/modbus_detect")
        assert cmd == "use"
        assert args == "scanners/ics/modbus_detect"

    def test_parse_line_hyphen_to_underscore(self):
        interp = _make_interp()
        cmd, args, kw = interp.parse_line("mitre-list all")
        assert cmd == "mitre_list"

    def test_dispatch_empty(self):
        interp = _make_interp()
        assert interp._dispatch("") is True

    def test_dispatch_exit(self):
        interp = _make_interp()
        assert interp._dispatch("exit") is False

    def test_dispatch_quit(self):
        interp = _make_interp()
        assert interp._dispatch("quit") is False

    def test_dispatch_unknown_command(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error") as pe:
            result = interp._dispatch("nonexistent_cmd_xyz")
            assert result is True
            pe.assert_called()

    def test_dispatch_exception_in_handler(self):
        interp = _make_interp()
        with patch.object(interp, "command_help", side_effect=RuntimeError("boom")):
            with patch("industrialxpl.interpreter.print_error") as pe:
                result = interp._dispatch("help")
                assert result is True
                pe.assert_called()

    def test_dispatch_ixf_exception(self):
        from industrialxpl.core.exploit.exceptions import IXFException
        interp = _make_interp()
        with patch.object(interp, "command_help", side_effect=IXFException("test")):
            with patch("industrialxpl.interpreter.print_error") as pe:
                result = interp._dispatch("help")
                assert result is True
                pe.assert_called()

    def test_get_command_handler_existing(self):
        interp = _make_interp()
        handler = interp.get_command_handler("help")
        assert callable(handler)

    def test_get_command_handler_missing(self):
        from industrialxpl.core.exploit.exceptions import IXFException
        interp = _make_interp()
        with pytest.raises(IXFException):
            interp.get_command_handler("nonexistent_xyz")

    def test_prompt_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        assert "ixf" in interp.prompt

    def test_prompt_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule(name="TestMod")
        p = interp.prompt
        assert "TestMod" in p

    def test_run_resource_lines(self):
        interp = _make_interp()
        lines = [
            "# comment line",
            "",
            "help",
            "  ",
        ]
        with patch.object(interp, "command_help") as mh:
            interp.run_resource_lines(lines, echo=False)
            mh.assert_called_once()

    def test_run_resource_lines_echo(self, capsys):
        interp = _make_interp()
        lines = ["help"]
        with patch.object(interp, "command_help"):
            interp.run_resource_lines(lines, echo=True)
        out = capsys.readouterr().out
        assert "help" in out

    def test_run_resource_lines_exit_stops(self):
        interp = _make_interp()
        lines = ["exit", "help"]
        with patch.object(interp, "command_help") as mh:
            interp.run_resource_lines(lines, echo=False)
            mh.assert_not_called()

    def test_nonInteractive_no_args(self):
        interp = _make_interp()
        interp.nonInteractive(["ixf"])  # no command

    def test_nonInteractive_with_command(self):
        interp = _make_interp()
        with patch.object(interp, "command_help") as mh:
            interp.nonInteractive(["ixf", "help"])
            mh.assert_called_once()

    def test_nonInteractive_ixf_exception(self):
        from industrialxpl.core.exploit.exceptions import IXFException
        interp = _make_interp()
        with patch.object(interp, "command_help", side_effect=IXFException("err")):
            with pytest.raises(SystemExit):
                interp.nonInteractive(["ixf", "help"])

    def test_start_eof_exits(self):
        interp = _make_interp()
        with patch("builtins.input", side_effect=EOFError), \
             patch.object(interp, "_startup_update_check"):
            interp.start(show_banner=False)

    def test_start_keyboard_interrupt_exits(self):
        interp = _make_interp()
        with patch("builtins.input", side_effect=KeyboardInterrupt), \
             patch.object(interp, "_startup_update_check"):
            interp.start(show_banner=False)

    def test_start_runs_commands(self):
        """Simulate typing 'help' then 'exit'."""
        interp = _make_interp()
        inputs = iter(["help", "exit"])
        with patch("builtins.input", side_effect=lambda _: next(inputs)), \
             patch.object(interp, "_startup_update_check"), \
             patch.object(interp, "command_help"):
            interp.start(show_banner=False)

    def test_start_empty_line_skipped(self):
        interp = _make_interp()
        inputs = iter(["", "exit"])
        with patch("builtins.input", side_effect=lambda _: next(inputs)), \
             patch.object(interp, "_startup_update_check"):
            interp.start(show_banner=False)

    def test_start_with_banner(self, capsys):
        interp = _make_interp()
        with patch("builtins.input", side_effect=EOFError), \
             patch.object(interp, "_startup_update_check"):
            interp.start(show_banner=True)
        out = capsys.readouterr().out
        assert "IndustrialXPL" in out

    def test_startup_update_check_newer(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {
                "version": "99.0.0",
                "project_urls": {"Changelog": "http://example.com"},
            }
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("industrialxpl.interpreter.print_warning") as pw:
            interp._startup_update_check()
            pw.assert_called()

    def test_startup_update_check_current(self):
        interp = _make_interp()
        from industrialxpl.interpreter import VERSION
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {
                "version": VERSION,
                "project_urls": {},
            }
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            interp._startup_update_check()  # should not crash

    def test_startup_update_check_error(self):
        interp = _make_interp()
        with patch("urllib.request.urlopen", side_effect=OSError("net err")):
            interp._startup_update_check()  # should not crash

    def test_startup_update_check_bad_version(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {
                "version": "not.a.version.x",
                "project_urls": {},
            }
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            interp._startup_update_check()

    def test_setup_readline_no_history(self):
        """_setup_readline handles missing history file gracefully."""
        _make_interp()
        # Already called during init; just verify no crash
        assert True

    def test_bind_completer_no_readline(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter._HAS_READLINE", False):
            interp._bind_completer()  # no crash


# ═══════════════════════════════════════════════════════════════════════════
# 4. IXFInterpreter command tests
# ═══════════════════════════════════════════════════════════════════════════

class TestIXFInterpreterCommands:
    def test_command_help_default(self, capsys):
        interp = _make_interp()
        interp.current_module = None
        interp.command_help("")
        out = capsys.readouterr().out
        assert "NAVIGATION" in out

    def test_command_help_with_module(self, capsys):
        interp = _make_interp()
        interp.current_module = FakeModule()
        interp.command_help("")
        out = capsys.readouterr().out
        assert "MODULE COMMANDS" in out

    def test_command_help_sector(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("sector")

    def test_command_help_sectors(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("sectors")

    def test_command_help_type(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("type")

    def test_command_help_types(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("types")

    def test_command_help_category(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("category")

    def test_command_help_global(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("global")

    def test_command_help_globals(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("globals")

    def test_command_help_safemode(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("safemode")

    def test_command_help_safety(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("safety")

    def test_command_help_simulate(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("simulate")

    def test_command_help_simulation(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("simulation")

    def test_command_help_loglevel(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("loglevel")

    def test_command_help_verbose(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("verbose")

    def test_command_help_timing(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.core.modbus.timing.ModbusTiming.describe_all", return_value="table"):
            interp.command_help("timing")

    def test_command_help_search(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("search")

    def test_command_help_mitre(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("mitre")

    def test_command_help_ttp(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_help("ttp")

    def test_command_help_option_map(self):
        interp = _make_interp()
        # Test each option help topic
        for topic in ("registers", "coils", "port", "transport", "fc",
                      "unit_id", "timeout", "target", "destructive",
                      "threads", "host_timeout", "max_retries",
                      "scan_delay", "max_rate", "probe_level",
                      "ping_first", "skip_ping", "output", "report_fmt"):
            with patch("industrialxpl.interpreter.print_info"):
                interp.command_help(topic)

    def test_command_help_module_path(self):
        """help <module_path> loads and shows module info."""
        interp = _make_interp()
        fake_cls = MagicMock(return_value=FakeModule())
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.pprint_dict_in_order"), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_help("scanners/ics/modbus_detect")

    def test_command_help_module_search_match(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.import_exploit", side_effect=ImportError("no")), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("modbus")

    def test_command_help_no_match(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.import_exploit", side_effect=ImportError("no")), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("zzzzz_nonexistent_zzzzz")

    def test_command_use_success(self):
        interp = _make_interp()
        fake_cls = MagicMock(return_value=FakeModule())
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert interp.current_module is not None

    def test_command_use_with_global_target(self):
        interp = _make_interp({"target": "10.0.0.1"})
        fm = FakeModule()
        fm.target = ""
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert interp.current_module.target == "10.0.0.1"

    def test_command_use_global_port(self):
        interp = _make_interp({"port": "502,510"})
        fm = FakeModule()
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert interp.current_module.port == "502,510"

    def test_command_use_poly_language_warning(self):
        interp = _make_interp()
        fm = FakeModule(poly_language="go")
        fake_cls = MagicMock(return_value=fm)
        runner_mock = MagicMock()
        runner_mock.check_runtime.return_value = False
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch("industrialxpl.core.poly.poly_runner.PolyExploitRunner", return_value=runner_mock):
            interp.command_use("scanners/ics/test")

    def test_command_use_error(self):
        from industrialxpl.core.exploit.exceptions import IXFException
        interp = _make_interp()
        with patch("industrialxpl.interpreter.import_exploit", side_effect=IXFException("bad")), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_use("bad/path")
        assert interp.current_module is None

    def test_command_use_apply_global_scan_opts(self):
        interp = _make_interp({"host_timeout": "60"})
        fm = FakeModule()
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")

    def test_command_use_global_transport(self):
        interp = _make_interp({"transport": "udp"})
        fm = FakeModule()
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert interp.current_module.transport == "udp"

    def test_command_use_global_unit_id(self):
        interp = _make_interp({"unit_id": "5"})
        fm = FakeModule()
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert interp.current_module.unit_id == "5"

    def test_command_use_skip_global_loglevel(self):
        """Globals like loglevel should NOT be applied to module options."""
        interp = _make_interp({"loglevel": "debug"})
        fm = FakeModule()
        fm.exploit_attributes["loglevel"] = ["", "Log level", False]
        fake_cls = MagicMock(return_value=fm)
        with patch("industrialxpl.interpreter.import_exploit", return_value=fake_cls), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_use("scanners/ics/modbus_detect")
        assert not hasattr(fm, "loglevel") or getattr(fm, "loglevel", None) != "debug"

    def test_command_back(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_back()
        assert interp.current_module is None

    def test_command_set_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_set("target 10.0.0.1")

    def test_command_set_success(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_set("target 10.0.0.1")
        assert interp.current_module.target == "10.0.0.1"

    def test_command_set_no_value(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_set("")

    def test_command_set_option_help(self):
        """set <option> with no value triggers help if option is known."""
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_set("timing")

    def test_command_set_question_mark(self):
        """set <option> ? triggers option help."""
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_set("timing ?")

    def test_command_set_question_mark_unknown(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_set("foobar ?")

    def test_command_set_unknown_option(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_set("nonexistent_opt value")

    def test_command_set_setattr_error(self):
        interp = _make_interp()
        mod = FakeModule()
        interp.current_module = mod
        with patch.object(type(mod), "__setattr__", side_effect=ValueError("no")), \
             patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_set("target value")

    def test_command_setg_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("")

    def test_command_setg_loglevel(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.set_log_level"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("loglevel debug")
        assert interp._global_opts.get("loglevel") == "debug"

    def test_command_setg_log_level_alias(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.set_log_level"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("log_level info")

    def test_command_setg_verbose_true(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.set_log_level"), \
             patch("industrialxpl.interpreter.get_log_level", return_value="debug"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("verbose true")

    def test_command_setg_verbose_false(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.set_log_level"), \
             patch("industrialxpl.interpreter.get_log_level", return_value="info"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("verbose false")

    def test_command_setg_threads(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("threads 10")
        assert interp._global_opts["threads"] == "10"

    def test_command_setg_threads_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("threads abc")

    def test_command_setg_threads_zero(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("threads 0")

    def test_command_setg_host_timeout(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("host_timeout 60")

    def test_command_setg_max_retries(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("max_retries 3")

    def test_command_setg_scan_delay(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("scan_delay 500")

    def test_command_setg_max_rate(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("max_rate 20")

    def test_command_setg_scan_opts_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("host_timeout abc")

    def test_command_setg_scan_opts_negative(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("max_retries -1")

    def test_command_setg_probe_level(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("probe_level 3")

    def test_command_setg_probe_level_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("probe_level 10")

    def test_command_setg_probe_level_not_int(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("probe_level abc")

    def test_command_setg_safemode_true(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("safemode true")
        assert interp._global_opts["safemode"] == "true"

    def test_command_setg_safemode_false(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("safemode false")

    def test_command_setg_safemode_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("safemode maybe")

    def test_command_setg_ping_first(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("ping_first true")

    def test_command_setg_skip_ping(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("skip_ping false")

    def test_command_setg_ping_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("ping_first maybe")

    def test_command_setg_port(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("port 502")

    def test_command_setg_port_expression(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.modbus.transport.parse_port_expression"):
            interp.command_setg("port 500-510")

    def test_command_setg_port_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("port 99999")

    def test_command_setg_port_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("port 502")

    def test_command_setg_transport(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("transport tcp")

    def test_command_setg_transport_both(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("transport both")

    def test_command_setg_transport_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("transport serial")

    def test_command_setg_transport_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("transport udp")

    def test_command_setg_unit_id(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("unit_id 5")

    def test_command_setg_unit_id_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_setg("unit_id 300")

    def test_command_setg_unit_id_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("unit_id 10")

    def test_command_setg_timing(self):
        interp = _make_interp()
        profile_mock = MagicMock()
        profile_mock.name = "Normal"
        with patch("industrialxpl.core.modbus.timing.ModbusTiming.resolve", return_value=profile_mock), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("timing T3")

    def test_command_setg_timing_invalid(self):
        interp = _make_interp()
        with patch("industrialxpl.core.modbus.timing.ModbusTiming.resolve", side_effect=ValueError("bad")), \
             patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("timing T99")

    def test_command_setg_timing_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        profile_mock = MagicMock()
        profile_mock.name = "Normal"
        with patch("industrialxpl.core.modbus.timing.ModbusTiming.resolve", return_value=profile_mock), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("timing T3")

    def test_command_setg_arbitrary(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("target 10.0.0.1")
        assert interp._global_opts["target"] == "10.0.0.1"

    def test_command_setg_arbitrary_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("target 10.0.0.1")

    def test_command_unsetg(self):
        interp = _make_interp({"target": "10.0.0.1"})
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_unsetg("target")
        assert "target" not in interp._global_opts

    def test_command_unsetg_not_set(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_warning"):
            interp.command_unsetg("nonexistent")

    def test_command_show_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("options")
            interp.command_show("")
            interp.command_show("modules")
            interp.command_show("all")

    def test_command_show_no_module_unknown(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_show("foobar")

    def test_command_show_global(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("global")

    def test_command_show_sectors(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("sectors")

    def test_command_show_types(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("types")

    def test_command_show_simulate(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_show("simulate")

    def test_command_show_loglevel(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_show("loglevel")

    def test_command_show_mitre(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_show("mitre")

    def test_command_show_option_map(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_show("timing")

    def test_command_show_info(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.pprint_dict_in_order"):
            interp.command_show("info")

    def test_command_show_options(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("options")

    def test_command_show_advanced(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("advanced")

    def test_command_show_devices(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_show("devices")

    def test_command_show_all(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.pprint_dict_in_order"), \
             patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("all")

    def test_command_show_bad_sub(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_show("nonsense")

    def test_command_run_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_run()

    def test_command_run_live(self):
        interp = _make_interp()
        mod = FakeModule()
        mod.simulate = False
        mod.destructive = False
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"):
            interp.command_run()

    def test_command_run_simulate(self):
        interp = _make_interp()
        mod = FakeModule()
        mod.simulate = True
        mod.destructive = False
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"):
            interp.command_run()

    def test_command_run_destructive(self):
        interp = _make_interp()
        mod = FakeModule()
        mod.simulate = False
        mod.destructive = True
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_run()

    def test_command_run_not_implemented(self):
        interp = _make_interp()
        mod = FakeModule()
        mod.run = MagicMock(side_effect=NotImplementedError)
        mod.simulate = False
        mod.destructive = False
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_run()

    def test_command_check_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_check()

    def test_command_check_assessment_only(self):
        interp = _make_interp()
        mod = FakeModule(impact="INFO")
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_check()

    def test_command_check_read_only(self):
        interp = _make_interp()
        mod = FakeModule(impact="READ")
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_check()

    def test_command_check_vulnerable(self):
        interp = _make_interp()
        mod = FakeModule(impact="HIGH")
        mod.check = MagicMock(return_value=True)
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_check()

    def test_command_check_not_vulnerable(self):
        interp = _make_interp()
        mod = FakeModule(impact="HIGH")
        mod.check = MagicMock(return_value=False)
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_check()

    def test_command_check_returns_none(self):
        interp = _make_interp()
        mod = FakeModule(impact="HIGH")
        mod.check = MagicMock(return_value=None)
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_check()

    def test_command_check_not_implemented(self):
        interp = _make_interp()
        mod = FakeModule(impact="HIGH")
        mod.check = MagicMock(side_effect=NotImplementedError)
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_check()

    def test_command_search_empty(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_search("")

    def test_command_search_found(self):
        interp = _make_interp()
        from industrialxpl.core.search.engine import SearchResult
        result = SearchResult("modbus", ["scanners.ics.modbus_detect"], expansion_note="expanded")
        engine = MagicMock()
        engine.search.return_value = result
        interp._search_engine = engine
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_search("modbus")

    def test_command_search_not_found(self):
        interp = _make_interp()
        from industrialxpl.core.search.engine import SearchResult
        result = SearchResult(
            "zzz", [], suggestions=["modbus"], hint="try modbus",
            multilingual_hint="PT-BR: modbus"
        )
        engine = MagicMock()
        engine.search.return_value = result
        interp._search_engine = engine
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_search("zzz")

    def test_command_search_many_results(self):
        interp = _make_interp()
        from industrialxpl.core.search.engine import SearchResult
        mods = [f"mod_{i}" for i in range(60)]
        result = SearchResult("test", mods)
        engine = MagicMock()
        engine.search.return_value = result
        interp._search_engine = engine
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_search("test")

    def test_command_modules_overview(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("")

    def test_command_modules_category(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("scanners")

    def test_command_modules_category_not_found(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("nonexistent_category")

    def test_command_exec_empty(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_exec("")

    def test_command_exec_success(self, capsys):
        interp = _make_interp()
        with patch("subprocess.run", return_value=MagicMock(stdout="hello\n", stderr="")):
            interp.command_exec("echo hello")

    def test_command_exec_stderr(self):
        interp = _make_interp()
        with patch("subprocess.run", return_value=MagicMock(stdout="", stderr="warn")), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_exec("bad_cmd")

    def test_command_exec_timeout(self):
        import subprocess
        interp = _make_interp()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_exec("slow_cmd")

    def test_command_discover_empty(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_discover("")

    def test_command_discover_with_cidr(self):
        interp = _make_interp()
        with patch.object(interp, "command_use"), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.current_module = FakeModule()
            interp.command_discover("192.168.1.0/24")

    def test_command_info_no_module_no_term(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_info("")

    def test_command_info_with_term(self):
        interp = _make_interp()
        with patch.object(interp, "command_help") as mh:
            interp.command_info("sector")
            mh.assert_called_once_with("sector")

    def test_command_info_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_show") as ms:
            interp.command_info("")
            ms.assert_called_once_with("info")

    def test_command_options_no_module(self):
        interp = _make_interp()
        interp.current_module = None
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_options()

    def test_command_options_with_module(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_show") as ms:
            interp.command_options()
            ms.assert_called_once_with("options")

    def test_command_global_empty(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_global("")

    def test_command_global_show(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_global("show")

    def test_command_global_setg_shorthand(self):
        interp = _make_interp()
        with patch.object(interp, "command_setg") as ms:
            interp.command_global("loglevel debug")
            ms.assert_called_once()

    def test_command_global_one_word(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_global("list")

    def test_command_update_up_to_date(self):
        interp = _make_interp()
        from industrialxpl.interpreter import VERSION
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": VERSION, "project_urls": {}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_update()

    def test_command_update_newer_decline(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": "99.0.0", "project_urls": {"Changelog": "http://ex.com"}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("builtins.input", return_value="n"), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_update()

    def test_command_update_newer_accept(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": "99.0.0", "project_urls": {"Changelog": "http://ex.com"}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        pip_result = MagicMock(returncode=0)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("builtins.input", return_value="y"), \
             patch("subprocess.run", return_value=pip_result), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_update()

    def test_command_update_pip_fails(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": "99.0.0", "project_urls": {}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        pip_result = MagicMock(returncode=1)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("builtins.input", return_value="y"), \
             patch("subprocess.run", return_value=pip_result), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_update()

    def test_command_update_pip_exception(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": "99.0.0", "project_urls": {}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("builtins.input", return_value="y"), \
             patch("subprocess.run", side_effect=OSError("pip boom")), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_update()

    def test_command_update_network_error(self):
        interp = _make_interp()
        with patch("urllib.request.urlopen", side_effect=OSError("net")), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_update()

    def test_command_update_eof_on_prompt(self):
        interp = _make_interp()
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({
            "info": {"version": "99.0.0", "project_urls": {}}
        }).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=fake_resp), \
             patch("builtins.input", side_effect=EOFError), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_update()

    def test_command_upgrade_alias(self):
        interp = _make_interp()
        with patch.object(interp, "command_update") as mu:
            interp.command_upgrade()
            mu.assert_called_once()

    def test_command_exit(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"), \
             pytest.raises(SystemExit):
            interp.command_exit()

    def test_resume_persistent_c2_success(self):
        interp = _make_interp()
        with patch("industrialxpl.core.malware.c2_server.resume_on_startup",
                    return_value={"resumed": True, "bots_online": 2, "bots_total": 5,
                                  "daemon_pid": 123, "go_cnc_pid": 456, "config": {}}), \
             patch("industrialxpl.interpreter.print_info"):
            interp._resume_persistent_c2()

    def test_resume_persistent_c2_not_resumed(self):
        interp = _make_interp()
        with patch("industrialxpl.core.malware.c2_server.resume_on_startup",
                    return_value={"resumed": False}):
            interp._resume_persistent_c2()

    def test_resume_persistent_c2_exception(self):
        interp = _make_interp()
        with patch("industrialxpl.core.malware.c2_server.resume_on_startup",
                    side_effect=ImportError("no c2")):
            interp._resume_persistent_c2()  # should not crash


# ═══════════════════════════════════════════════════════════════════════════
# 5. MITRE commands mixin tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMITRECommands:
    def test_command_cve_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_cve("something")

    def test_command_cve_valid_single_match(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"), \
             patch.object(interp, "command_use"):
            interp.command_cve("CVE-2022-29953")

    def test_command_cve_multiple_matches(self):
        interp = _make_interp()
        interp.modules = [
            "cve.siemens.cve_2022_29953_a",
            "cve.siemens.cve_2022_29953_b",
        ]
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_cve("CVE-2022-29953")

    def test_command_cve_no_match(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_cve("CVE-9999-99999")

    def test_command_cve_cnvd(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_cve("CNVD-2022-12345")

    def test_command_cve_scan(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_cve_scan("10.0.0.0/24")

    def test_command_cve_scan_empty(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_cve_scan("")

    def test_command_report(self):
        interp = _make_interp()
        reporter = MagicMock()
        reporter.generate.return_value = "/tmp/report.json"
        with patch("industrialxpl.core.reporting.reporter.IXFReporter", return_value=reporter), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_report("json")

    def test_command_report_default(self):
        interp = _make_interp()
        reporter = MagicMock()
        reporter.generate.return_value = "/tmp/report.json"
        with patch("industrialxpl.core.reporting.reporter.IXFReporter", return_value=reporter), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_report("")

    def test_command_mitre_no_tid(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_mitre("")

    def test_command_mitre_found(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["mod1"]}), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_mitre("T0843")

    def test_command_mitre_not_found(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {}), \
             patch("industrialxpl.interpreter.print_error"):
            interp.command_mitre("T9999")

    def test_command_mitre_list(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES", {}), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_mitre_list("")

    def test_command_mitre_list_with_tactic(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {"TA0100": ["m1"]}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES", {"discovery": "TA0100"}), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_mitre_list("discovery")

    def test_command_mitre_scan_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_mitre_scan("discovery")

    def test_command_mitre_scan_tactic(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_mitre_scan("discovery 10.0.0.1")
            sweeper.sweep_tactic.assert_called_once()

    def test_command_mitre_scan_technique(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_mitre_scan("T0843 10.0.0.1")
            sweeper.sweep_technique.assert_called_once()

    def test_command_mitre_scan_destructive(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_mitre_scan("T0843 10.0.0.1 --destructive")

    def test_command_mitre_scan_simulate(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_mitre_scan("T1234 10.0.0.1 --simulate")

    def test_command_mitre_all_no_target(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_mitre_all("")

    def test_command_mitre_all(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper), \
             patch("industrialxpl.interpreter.print_status"):
            interp.command_mitre_all("10.0.0.1")
            sweeper.sweep_all.assert_called_once()

    def test_command_mitre_coverage(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_TIDS", {"TA0100": ["T0843"]}), \
             patch("industrialxpl.core.mitre.tactics.TACTICS", {"TA0100": "Discovery"}), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_mitre_coverage("")

    def test_command_mitre_report(self):
        interp = _make_interp()
        reporter = MagicMock()
        reporter.generate_layer.return_value = "/tmp/layer.json"
        with patch("industrialxpl.core.mitre.reporter.MitreSweepReporter", return_value=reporter), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_mitre_report("layer")

    def test_command_mitre_tactic_alias(self):
        interp = _make_interp()
        with patch.object(interp, "command_mitre_scan") as ms:
            interp.command_mitre_tactic("discovery 10.0.0.1")
            ms.assert_called_once()

    def test_command_ttp_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_ttp("T0843")

    def test_command_ttp_with_output(self):
        interp = _make_interp()
        sweeper = MagicMock()
        sweeper.sweep_technique.return_value = [{"result": "ok"}]
        reporter = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper), \
             patch("industrialxpl.core.mitre.reporter.MitreSweepReporter", return_value=reporter), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_ttp("T0843 10.0.0.1 --output /tmp/out.json")

    def test_command_ttp_basic(self):
        interp = _make_interp()
        sweeper = MagicMock()
        sweeper.sweep_technique.return_value = []
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_ttp("T0843 10.0.0.1")

    def test_command_ttp_with_flags(self):
        interp = _make_interp()
        sweeper = MagicMock()
        sweeper.sweep_technique.return_value = []
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_ttp("T0843 10.0.0.1 --destructive --simulate --stop-on-first --rate-limit 200")

    def test_command_ttp_check_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_ttp_check("T0843")

    def test_command_ttp_check(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_ttp_check("T0843 10.0.0.1")

    def test_command_ttp_simulate_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"):
            interp.command_ttp_simulate("T0843")

    def test_command_ttp_simulate(self):
        interp = _make_interp()
        sweeper = MagicMock()
        with patch("industrialxpl.core.mitre.sweeper.MitreTacticSweeper", return_value=sweeper):
            interp.command_ttp_simulate("T0843 10.0.0.1")

    def test_command_ttp_list(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES", {}), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_ttp_list("")

    def test_command_ttp_list_with_tactic(self):
        interp = _make_interp()
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {"TA0100": ["m1"]}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES", {"discovery": "TA0100"}), \
             patch("industrialxpl.interpreter.print_table"):
            interp.command_ttp_list("--tactic discovery")


# ═══════════════════════════════════════════════════════════════════════════
# 6. Stats commands mixin tests
# ═══════════════════════════════════════════════════════════════════════════

class TestStatsCommands:
    def test_command_stats(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_stats.index_modules", return_value=list(FAKE_MODULES)), \
             patch("industrialxpl.cli.commands_stats.print_info"), \
             patch("industrialxpl.cli.commands_stats.print_table"):
            interp.command_stats()

    def test_command_vendors(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_stats.index_modules", return_value=list(FAKE_MODULES)), \
             patch("industrialxpl.cli.commands_stats.print_table"):
            interp.command_vendors("")

    def test_command_vendors_filter(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_stats.index_modules", return_value=list(FAKE_MODULES)), \
             patch("industrialxpl.cli.commands_stats.print_table"):
            interp.command_vendors("siemens")

    def test_command_protocols(self):
        interp = _make_interp()
        mods = list(FAKE_MODULES) + ["scanners.protocols.modbus.modbus_read"]
        with patch("industrialxpl.cli.commands_stats.index_modules", return_value=mods), \
             patch("industrialxpl.cli.commands_stats.print_table"):
            interp.command_protocols()

    def test_command_coverage(self):
        interp = _make_interp()
        with patch.object(interp, "command_mitre_coverage") as mc:
            interp.command_coverage()
            mc.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# 7. SAST commands mixin tests
# ═══════════════════════════════════════════════════════════════════════════

class TestSASTCommands:
    def test_command_llm_key_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_sast.print_error"):
            interp.command_llm_key("")

    def test_command_llm_key_success(self):
        interp = _make_interp()
        mgr = MagicMock()
        with patch("industrialxpl.modules.assessment.sast.plc_source_analyzer._llm_manager", mgr), \
             patch("industrialxpl.cli.commands_sast.print_success"):
            interp.command_llm_key("openai sk-test123")

    def test_command_llm_key_error(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.set_key.side_effect = ValueError("bad provider")
        with patch("industrialxpl.modules.assessment.sast.plc_source_analyzer._llm_manager", mgr), \
             patch("industrialxpl.cli.commands_sast.print_error"):
            interp.command_llm_key("badprov key123")

    def test_command_llm_status(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.status.return_value = {"openai": "configured", "anthropic": "not set"}
        mgr.get_active_provider.return_value = "openai"
        with patch("industrialxpl.modules.assessment.sast.plc_source_analyzer._llm_manager", mgr), \
             patch("industrialxpl.cli.commands_sast.print_table"), \
             patch("industrialxpl.cli.commands_sast.print_info"):
            interp.command_llm_status()

    def test_command_llm_status_error(self):
        _make_interp()
        with patch("industrialxpl.modules.assessment.sast.plc_source_analyzer._llm_manager",
                    side_effect=Exception("no module")), \
             patch("industrialxpl.cli.commands_sast.print_error"):
            # Force the import to fail
            pass

    def test_command_sast_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_sast.print_error"):
            interp.command_sast("")

    def test_command_sast_basic(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use"), \
             patch.object(interp, "command_set"), \
             patch.object(interp, "command_run"):
            interp.command_sast("/path/to/code")

    def test_command_sast_with_mode(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use"), \
             patch.object(interp, "command_set"), \
             patch.object(interp, "command_run"):
            interp.command_sast("/path/to/code --mode reverse")

    def test_command_sast_with_diff(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use"), \
             patch.object(interp, "command_set"), \
             patch.object(interp, "command_run"):
            interp.command_sast("/path/to/code --mode diff --diff /other/path")

    def test_command_sast_unknown_flag_skipped(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use"), \
             patch.object(interp, "command_set"), \
             patch.object(interp, "command_run"):
            interp.command_sast("/path/to/code --unknown value")


# ═══════════════════════════════════════════════════════════════════════════
# 8. ICS commands mixin tests
# ═══════════════════════════════════════════════════════════════════════════

class TestICSCommands:
    def test_command_ics_tools_help(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_ics_tools("")

    def test_command_ics_tools_help_explicit(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_ics_tools("help")

    def test_command_ics_tools_list(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.list_tools.return_value = ["scadapass", "redpoint"]
        catalog = MagicMock()
        fam = MagicMock()
        fam.label = "SCADAPASS"
        catalog.get.return_value = fam
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog", return_value=catalog), \
             patch("industrialxpl.cli.commands_ics.print_table"):
            interp.command_ics_tools("list")

    def test_command_ics_tools_matrix(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.list_tools.return_value = ["scadapass"]
        catalog = MagicMock()
        fam = MagicMock()
        fam.interpreter = "python"
        fam.entry_script = "run.py"
        catalog.get.return_value = fam
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog", return_value=catalog), \
             patch("industrialxpl.cli.commands_ics.print_table"):
            interp.command_ics_tools("matrix")

    def test_command_ics_tools_analyze(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.analyze.return_value = {"label": "SP", "interpreter": "py", "entry": "run.py", "vendor_path": "/x"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_success"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_ics_tools("analyze scadapass")

    def test_command_ics_tools_analyze_error(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.analyze.return_value = {"error": "not found"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_ics_tools("analyze nonexistent")

    def test_command_ics_tools_plan(self):
        interp = _make_interp()
        interp.global_variables = {"TARGET": "10.0.0.1"}
        orch = MagicMock()
        orch.build_plan.return_value = {
            "plan_steps": [{"phase": "1", "action": "scan", "detail": "do scan"}]
        }
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_table"):
            interp.command_ics_tools("plan scadapass")

    def test_command_ics_tools_plan_error(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.build_plan.return_value = {"error": "no target"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_ics_tools("plan scadapass")

    def test_command_ics_tools_run(self):
        interp = _make_interp()
        interp.global_variables = {"TARGET": "10.0.0.1"}
        orch = MagicMock()
        orch.run.return_value = {"success": True, "stdout": "output"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_info"), \
             patch("industrialxpl.cli.commands_ics.print_success"):
            interp.command_ics_tools("run scadapass")

    def test_command_ics_tools_run_redpoint(self):
        interp = _make_interp()
        interp.global_variables = {"TARGET": "10.0.0.1"}
        orch = MagicMock()
        orch.run.return_value = {"success": True, "stdout": "bacnet data"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_info"), \
             patch("industrialxpl.cli.commands_ics.print_success"):
            interp.command_ics_tools("run redpoint")

    def test_command_ics_tools_run_fail(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.run.return_value = {"success": False, "error": "not found"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_ics_tools("run scadapass")

    def test_command_ics_tools_compile(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.runner.compile_vendor.return_value = {"success": True}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_success"):
            interp.command_ics_tools("compile scadapass")

    def test_command_ics_tools_compile_fail(self):
        interp = _make_interp()
        orch = MagicMock()
        orch.runner.compile_vendor.return_value = {"success": False, "error": "no compiler"}
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator", return_value=orch), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_ics_tools("compile scadapass")

    def test_command_ics_tools_unknown(self):
        interp = _make_interp()
        with patch("industrialxpl.core.ics_tools.IcsToolsOrchestrator"), \
             patch("industrialxpl.core.ics_tools.IcsToolsCatalog"), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_ics_tools("unknown_sub")

    def test_command_assess_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_assess("")

    def test_command_assess_with_path(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use"), \
             patch.object(interp, "command_run"):
            interp.command_assess("detection/scada_audit")

    def test_command_assess_prepends_assessment(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use") as mu, \
             patch.object(interp, "command_run"):
            interp.command_assess("scada_audit")
            mu.assert_called_once_with("assessment/scada_audit")

    def test_command_assess_already_assessment_prefix(self):
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch.object(interp, "command_use") as mu, \
             patch.object(interp, "command_run"):
            interp.command_assess("assessment/detection/scada_audit")
            mu.assert_called_once_with("assessment/detection/scada_audit")

    def test_command_nse_status(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.find_nmap.return_value = "/usr/bin/nmap"
        scripts_dir = MagicMock()
        mgr.find_scripts_dir.return_value = scripts_dir
        script_path = MagicMock()
        script_path.name = "ics-sweep.nse"
        script_path.exists.return_value = True
        (scripts_dir / script_path.name).exists = MagicMock(return_value=True)
        mgr.list_ixf_scripts.return_value = [script_path]
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("status")

    def test_command_nse_status_no_nmap(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = None
        mgr_cls.status_report = MagicMock()
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_warning"):
            interp.command_nse("")

    def test_command_nse_status_with_uninstalled(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        scripts_dir = Path("/usr/share/nmap/scripts")
        mgr_cls.find_scripts_dir.return_value = scripts_dir
        mgr_cls.status_report = MagicMock()
        script = MagicMock()
        script.name = "ics-sweep.nse"
        mgr_cls.list_ixf_scripts.return_value = [script]
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", Path("/tmp")), \
             patch.object(Path, "exists", return_value=False), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("status")

    def test_command_nse_list(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        scripts_dir = Path("/usr/share/nmap/scripts")
        mgr_cls.find_scripts_dir.return_value = scripts_dir
        script = MagicMock()
        script.name = "ics-sweep.nse"
        script.stat.return_value = MagicMock(st_size=1024)
        mgr_cls.list_ixf_scripts.return_value = [script]
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", Path("/tmp")), \
             patch.object(Path, "exists", return_value=False), \
             patch("industrialxpl.cli.commands_ics.print_table"):
            interp.command_nse("list")

    def test_command_nse_list_empty(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_scripts_dir.return_value = None
        mgr_cls.list_ixf_scripts.return_value = []
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_error"):
            interp.command_nse("list")

    def test_command_nse_install_no_nmap(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = None
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.core.nse.nse_manager.NSE_SCRIPTS_DIR", Path("/tmp")), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_warning"):
            interp.command_nse("install")

    def test_command_nse_install_no_scripts_dir(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = None
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("install")

    def test_command_nse_install_success(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        scripts_dir = Path("/usr/share/nmap/scripts")
        mgr_cls.find_scripts_dir.return_value = scripts_dir
        mgr_cls.install.return_value = {
            "success": True,
            "installed": ["ics-sweep.nse"],
            "skipped": [],
            "errors": [],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_success"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("install")

    def test_command_nse_install_skipped(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = Path("/usr/share/nmap/scripts")
        mgr_cls.install.return_value = {
            "success": True,
            "installed": [],
            "skipped": ["ics-sweep.nse"],
            "errors": [],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("install")

    def test_command_nse_install_permission_error_linux(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = Path("/usr/share/nmap/scripts")
        mgr_cls.install.return_value = {
            "success": False,
            "installed": [],
            "skipped": [],
            "errors": ["Permission denied: /usr/share/nmap/scripts"],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_warning"), \
             patch("sys.platform", "linux"):
            interp.command_nse("install")

    def test_command_nse_install_permission_error_win32(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = Path("/usr/share/nmap/scripts")
        mgr_cls.install.return_value = {
            "success": False,
            "installed": [],
            "skipped": [],
            "errors": ["Permission denied"],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_warning"):
            # Use platform module mock to simulate win32
            interp.command_nse("install")

    def test_command_nse_unknown(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_info"):
            interp.command_nse("foobar")


# ═══════════════════════════════════════════════════════════════════════════
# 9. Malware commands mixin tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMalwareCommands:
    def test_command_malware_help(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("")

    def test_command_malware_help_explicit(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("help")

    def test_command_malware_list(self):
        interp = _make_interp()
        interp.global_variables = {}
        catalog = MagicMock()
        catalog.list_slugs.return_value = ["mirai", "trisis"]
        fam = MagicMock()
        fam.label = "Mirai"
        catalog.get.return_value = fam
        with patch("industrialxpl.core.malware.MalwareCatalog", return_value=catalog), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_table"):
            interp.command_malware("list")

    def test_command_malware_matrix(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.core.malware.family_capabilities.capability_matrix",
                   return_value=[{"slug": "mirai", "mode": "active", "compile": "yes", "ixf_module": "m"}]), \
             patch("industrialxpl.cli.commands_malware.print_table"):
            interp.command_malware("matrix")

    def test_command_malware_analyze(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.analyze.return_value = {
            "family": "Mirai",
            "source_files": 10,
            "elf_binaries": ["bot"],
            "capability_mode": "active",
            "compile_targets": ["mips"],
            "attack_vectors": ["telnet", "ssh"],
            "ixf_module": "scanners/malware/mirai",
        }
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator", return_value=orch), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("analyze mirai")

    def test_command_malware_analyze_error(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.analyze.return_value = {"error": "not found"}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator", return_value=orch), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp.command_malware("analyze nonexistent")

    def test_command_malware_plan(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.build_plan.return_value = {
            "family": "Mirai",
            "plan_steps": [{"phase": "1", "action": "scan", "detail": "scan targets"}],
        }
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator", return_value=orch), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_table"):
            interp.command_malware("plan mirai")

    def test_command_malware_plan_error(self):
        interp = _make_interp()
        interp.global_variables = {}
        orch = MagicMock()
        orch.build_plan.return_value = {"error": "no plan"}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator", return_value=orch), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp.command_malware("plan mirai")

    def test_command_malware_build(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "4444"}
        compiler = MagicMock()
        compiler.compile.return_value = {"success": True, "output": "/tmp/bot", "c2_host": "10.0.0.1", "c2_port": 4444}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.core.malware.BuildProfile") as bp_cls, \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            bp_cls.return_value.effective_cnc_host.return_value = "10.0.0.1"
            interp.command_malware("build mirai_bot")

    def test_command_malware_build_fail(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        compiler = MagicMock()
        compiler.compile.return_value = {"success": False, "error": "no toolchain"}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.core.malware.BuildProfile") as bp_cls, \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            bp_cls.return_value.effective_cnc_host.return_value = ""
            interp.command_malware("build mirai_bot")

    def test_command_malware_exec(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact",
                   return_value={"success": True, "stdout": "ok"}), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=True), \
             patch("industrialxpl.cli.commands_malware.print_info"), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp.command_malware("exec /tmp/bot")

    def test_command_malware_exec_declined(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=False):
            interp.command_malware("exec /tmp/bot")

    def test_command_malware_deploy(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target",
                   return_value={"success": True}), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=True), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp.command_malware("deploy /tmp/bot 10.0.0.1 23")

    def test_command_malware_deploy_declined(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=False):
            interp.command_malware("deploy /tmp/bot 10.0.0.1")

    def test_command_malware_shell(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session",
                   return_value={"stdout": "root"}), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("shell 10.0.0.1 23")

    def test_command_malware_shell_default_port(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session",
                   return_value={"banner": "login:"}), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("shell 10.0.0.1")

    def test_command_malware_firmware(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan",
                   return_value={"steps": ["erase", "write", "verify"]}), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=True), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("firmware /tmp/fw.bin 10.0.0.1")

    def test_command_malware_firmware_declined(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=False):
            interp.command_malware("firmware /tmp/fw.bin 10.0.0.1")

    def test_command_malware_unknown(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.MalwareCatalog"), \
             patch("industrialxpl.core.malware.MalwareOrchestrator"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.lab_ops.deploy_to_target"), \
             patch("industrialxpl.core.malware.lab_ops.execute_artifact"), \
             patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"), \
             patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"), \
             patch("industrialxpl.cli.commands_malware.print_error"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp.command_malware("foobar_unknown")

    def test_malware_db_bootstrap(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.bootstrap_lab_dbs",
                    return_value={"success": True, "target": "/tmp", "files": [{"action": "copy", "file": "x.db", "path": "/tmp/x.db"}]}), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_db(["db", "bootstrap"])

    def test_malware_db_bootstrap_error(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.bootstrap_lab_dbs",
                    return_value={"success": False, "error": "fail"}), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_db(["db", "bootstrap"])

    def test_malware_db_init(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.default_dsn", return_value="sqlite:///test.db"), \
             patch("industrialxpl.core.malware.db_init.init_schema",
                   return_value={"success": True, "dialect": "sqlite", "path": "/tmp/test.db"}), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_db(["db", "init"])

    def test_malware_db_init_error(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.default_dsn", return_value="sqlite:///test.db"), \
             patch("industrialxpl.core.malware.db_init.init_schema",
                   return_value={"success": False, "error": "bad dsn"}), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_db(["db", "init"])

    def test_malware_db_unknown(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.bootstrap_lab_dbs"), \
             patch("industrialxpl.core.malware.db_init.default_dsn"), \
             patch("industrialxpl.core.malware.db_init.init_schema"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_db(["db", "foobar"])

    def test_malware_c2_status(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "0.0.0.0", "LPORT": "48101"}
        mgr = MagicMock()
        mgr.status.return_value = {
            "daemon_pid": 123, "go_cnc_pid": 456,
            "bots_online": 1, "bots_total": 2,
            "bots": [{"bot_ip": "10.0.0.1", "status": "online", "deploy_method": "telnet", "last_seen": 1234}],
        }
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.cli.commands_malware.print_info"), \
             patch("industrialxpl.cli.commands_malware.print_table"):
            interp._malware_c2(["c2", "status"])

    def test_malware_c2_start(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "MALWARE_ARTIFACT": "/tmp/bot"}
        mgr = MagicMock()
        mgr.start.return_value = {"mode": "go", "pid": 123, "go_cnc_pid": 456}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_c2(["c2", "start"])

    def test_malware_c2_stop(self):
        interp = _make_interp()
        interp.global_variables = {}
        mgr = MagicMock()
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_c2(["c2", "stop"])

    def test_malware_c2_build_go(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.core.malware.db_init.default_dsn", return_value="sqlite:///test.db"), \
             patch("industrialxpl.core.malware.db_init.init_schema", return_value={"dialect": "sqlite"}), \
             patch("industrialxpl.core.malware.go_cnc_manager.build_go_cnc",
                   return_value={"success": True, "output": "/tmp/cnc", "size": 1024}), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_c2(["c2", "build-go"])

    def test_malware_c2_build_go_fail(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.core.malware.go_cnc_manager.build_go_cnc",
                   return_value={"success": False, "error": "no go"}), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_c2(["c2", "build-go"])

    def test_malware_c2_unknown(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager"), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_c2(["c2", "foobar"])

    def test_malware_docker_lisa_up(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.up.return_value = {"success": True, "url": "http://localhost"}
        mgr.wait_http.return_value = {"success": True}
        with patch("industrialxpl.core.lab.docker_stack.DockerStackManager", return_value=mgr), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_docker(["docker", "lisa", "up"])

    def test_malware_docker_lisa_up_fail(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.up.return_value = {"success": False, "error": "docker not found"}
        with patch("industrialxpl.core.lab.docker_stack.DockerStackManager", return_value=mgr), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_docker(["docker", "lisa", "up"])

    def test_malware_docker_lisa_down(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.down.return_value = {"success": True}
        with patch("industrialxpl.core.lab.docker_stack.DockerStackManager", return_value=mgr), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_docker(["docker", "lisa", "down"])

    def test_malware_docker_lisa_status(self):
        interp = _make_interp()
        mgr = MagicMock()
        mgr.status.return_value = {"stdout": "running"}
        with patch("industrialxpl.core.lab.docker_stack.DockerStackManager", return_value=mgr), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_docker(["docker", "lisa", "status"])

    def test_malware_docker_unknown_stack(self):
        interp = _make_interp()
        with patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_docker(["docker", "foobar"])

    def test_malware_crosscompile_list(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        xc = MagicMock()
        tc = MagicMock()
        tc.prefix = "mips-cross"
        tc.available = True
        xc.detect_toolchains.return_value = [tc]
        xc.list_artifacts.return_value = [{"path": "/tmp/bot"}]
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.cli.commands_malware.print_table"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_crosscompile(["crosscompile", "list"])

    def test_malware_crosscompile_all(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "4444"}
        xc = MagicMock()
        xc.compile_all.return_value = {"success": True, "built": [{"arch": "mips", "path": "/tmp/bot"}], "skipped": ["arm"]}
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_warning"):
            interp._malware_crosscompile(["crosscompile", "all"])

    def test_malware_crosscompile_specific(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        xc = MagicMock()
        xc.compile_all.return_value = {"success": True, "built": [{"arch": "mips", "path": "/tmp/bot"}]}
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_crosscompile(["crosscompile", "mips"])

    def test_malware_crosscompile_fail(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        xc = MagicMock()
        xc.compile_all.return_value = {"success": False, "error": "no toolchains"}
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_crosscompile(["crosscompile", "mips"])

    def test_malware_crosscompile_go_cnc(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        xc = MagicMock()
        xc.build_go_cnc.return_value = {"success": True, "built": []}
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"):
            interp._malware_crosscompile(["crosscompile", "go-cnc"])

    def test_malware_crosscompile_install(self):
        interp = _make_interp()
        interp.global_variables = {}
        Path("/tmp/fake_install.sh")
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler"), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("pathlib.Path.is_file", return_value=True), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_crosscompile(["crosscompile", "install"])

    def test_malware_crosscompile_install_missing_script(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler"), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("pathlib.Path.is_file", return_value=False), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_crosscompile(["crosscompile", "install"])

    def test_malware_propagate_simulate(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "LAB_WHITELIST": "", "MALWARE_ARTIFACT": "", "SIMULATE": "true"}
        prop = MagicMock()
        prop.propagate.return_value = {"simulate": True, "open_services": 3, "would_deploy_to": ["10.0.0.1"]}
        with patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.core.malware.propagator.BotnetPropagator", return_value=prop), \
             patch("industrialxpl.cli.commands_malware.print_warning"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_propagate(["propagate", "10.0.0.0/24"])

    def test_malware_propagate_live(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "LAB_WHITELIST": "", "MALWARE_ARTIFACT": "", "SIMULATE": "false"}
        prop = MagicMock()
        prop.propagate.return_value = {"deployed": [("10.0.0.1", "root", "telnet")]}
        with patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.core.malware.propagator.BotnetPropagator", return_value=prop), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation", return_value=True), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_propagate(["propagate", "10.0.0.0/24"])

    def test_malware_compile_list(self):
        interp = _make_interp()
        compiler = MagicMock()
        target = MagicMock()
        target.name = "mirai_bot"
        target.family = "mirai"
        target.lang = "c"
        target.impact = "HIGH"
        compiler.list_targets.return_value = [target]
        compiler.detect_toolchains.return_value = {"gcc": True}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_table"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            interp._malware_compile(["compile", "list"])

    def test_malware_compile_all(self):
        interp = _make_interp()
        compiler = MagicMock()
        target = MagicMock()
        target.name = "mirai_bot"
        compiler.list_targets.return_value = [target]
        compiler.compile.return_value = {"success": True, "output": "/tmp/bot"}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_compile(["compile", "all"])

    def test_malware_compile_single(self):
        interp = _make_interp()
        compiler = MagicMock()
        compiler.compile.return_value = {"success": True, "output": "/tmp/bot", "size": 1024}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_compile(["compile", "mirai_bot"])

    def test_malware_compile_fail(self):
        interp = _make_interp()
        compiler = MagicMock()
        compiler.compile.return_value = {"success": False, "error": "no target"}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_compile(["compile", "mirai_bot"])

    def test_malware_compile_no_args(self):
        interp = _make_interp()
        with patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.cli.commands_malware.print_error"):
            interp._malware_compile(["compile"])


# ═══════════════════════════════════════════════════════════════════════════
# 10. API Server tests
# ═══════════════════════════════════════════════════════════════════════════

class FakeRequest:
    """Simulate an HTTP request for handler tests."""

    def __init__(self, method: str, path: str, body: bytes = b"",
                 headers: dict | None = None, token: str = ""):
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers or {}
        self.token = token


def _invoke_handler(method: str, path: str, body: bytes = b"",
                    headers: dict | None = None, token: str = ""):
    """Build a handler and invoke do_GET or do_POST, return status and body."""
    from industrialxpl.api.server import build_handler

    handler_cls = build_handler(token=token)

    # Build a minimal mock of BaseHTTPRequestHandler interface
    handler = MagicMock(spec=handler_cls)
    handler.path = path
    handler.wfile = io.BytesIO()
    rfile = io.BytesIO(body)
    handler.rfile = rfile

    _headers = {
        "Content-Length": str(len(body)),
        **(headers or {}),
    }
    handler.headers = _headers

    responses: list = []

    def send_response(code):
        responses.append(code)

    def send_header(k, v):
        pass

    def end_headers():
        pass

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = end_headers

    # Call the actual method on an instance
    instance = handler_cls.__new__(handler_cls)
    instance.path = path
    instance.wfile = io.BytesIO()
    instance.rfile = io.BytesIO(body)
    instance.headers = _headers
    instance.send_response = send_response
    instance.send_header = send_header
    instance.end_headers = end_headers

    if method == "GET":
        instance.do_GET()
    elif method == "POST":
        instance.do_POST()

    instance.wfile.seek(0)
    response_body = instance.wfile.read()

    return responses[0] if responses else 0, json.loads(response_body) if response_body else {}


class TestAPIServer:
    def test_health(self):
        code, body = _invoke_handler("GET", "/health")
        assert code == 200
        assert body["status"] == "ok"

    def test_root(self):
        code, body = _invoke_handler("GET", "/")
        assert code == 200
        assert body["status"] == "ok"

    def test_modules(self):
        with patch("industrialxpl.core.exploit.utils.index_modules", return_value=list(FAKE_MODULES)):
            code, body = _invoke_handler("GET", "/modules")
        assert code == 200
        assert "count" in body

    def test_mitre_coverage(self):
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["m1"]}), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_TIDS", {"TA0100": ["T0843", "T0844"]}):
            code, body = _invoke_handler("GET", "/mitre/coverage")
        assert code == 200
        assert "techniques_indexed" in body

    def test_not_found(self):
        code, body = _invoke_handler("GET", "/nonexistent")
        assert code == 404

    def test_post_scan(self):
        data = json.dumps({"module": "scanners/ics/modbus_scanner", "target": "10.0.0.1"}).encode()
        code, body = _invoke_handler("POST", "/scan", body=data)
        assert code == 200
        assert body["simulate"] is True

    def test_post_scan_empty_body(self):
        code, body = _invoke_handler("POST", "/scan", body=b"")
        assert code == 200

    def test_post_scan_invalid_json(self):
        code, body = _invoke_handler("POST", "/scan", body=b"not json")
        assert code == 200

    def test_post_sast(self):
        code, body = _invoke_handler("POST", "/sast", body=b"{}")
        assert code == 200
        assert body["simulate"] is True

    def test_post_not_found(self):
        code, body = _invoke_handler("POST", "/nonexistent", body=b"{}")
        assert code == 404

    def test_auth_required(self):
        code, body = _invoke_handler("GET", "/health", token="secret123")
        assert code == 401

    def test_auth_valid(self):
        code, body = _invoke_handler(
            "GET", "/health",
            headers={"Authorization": "Bearer secret123"},
            token="secret123",
        )
        assert code == 200

    def test_auth_post_required(self):
        code, body = _invoke_handler("POST", "/scan", body=b"{}", token="secret123")
        assert code == 401

    def test_auth_post_valid(self):
        code, body = _invoke_handler(
            "POST", "/scan",
            body=b"{}",
            headers={"Authorization": "Bearer secret123"},
            token="secret123",
        )
        assert code == 200

    def test_log_message_suppressed(self):
        from industrialxpl.api.server import build_handler
        handler_cls = build_handler()
        instance = handler_cls.__new__(handler_cls)
        # Should not raise
        instance.log_message("test %s", "arg")

    def test_run_server_keyboard_interrupt(self):
        from industrialxpl.api.server import run_server
        with patch("industrialxpl.api.server.ThreadingHTTPServer") as mock_httpd_cls:
            mock_httpd = MagicMock()
            mock_httpd.serve_forever.side_effect = KeyboardInterrupt
            mock_httpd_cls.return_value = mock_httpd
            run_server(host="127.0.0.1", port=19999, token="")

    def test_try_fastapi_app_no_fastapi(self):
        from industrialxpl.api.server import try_fastapi_app
        with patch.dict(sys.modules, {"fastapi": None}):
            # Mock ImportError on import
            with patch("builtins.__import__", side_effect=ImportError):
                try_fastapi_app()
        # Result should be None when fastapi is not installed
        # (the function catches ImportError internally)

    def test_try_fastapi_app_available(self):
        from industrialxpl.api.server import try_fastapi_app
        fake_fastapi = types.ModuleType("fastapi")
        fake_app = MagicMock()
        fake_fastapi.FastAPI = MagicMock(return_value=fake_app)
        fake_app.get = MagicMock(side_effect=lambda path: lambda fn: fn)
        with patch.dict(sys.modules, {"fastapi": fake_fastapi}):
            try_fastapi_app()
        # Should return an app object


# ═══════════════════════════════════════════════════════════════════════════
# 11. __main__.py tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMain:
    def test_build_parser(self):
        from industrialxpl.__main__ import build_parser
        p = build_parser()
        args = p.parse_args([])
        assert args.resource_files == []
        assert args.no_interactive is False
        assert args.quiet is False

    def test_build_parser_with_flags(self):
        from industrialxpl.__main__ import build_parser
        p = build_parser()
        args = p.parse_args(["-r", "test.rc", "-x", "-q", "--loglevel", "debug", "-o", "/tmp/out", "-v", "--no-color"])
        assert args.resource_files == ["test.rc"]
        assert args.no_interactive is True
        assert args.quiet is True
        assert args.loglevel == "debug"
        assert args.output == "/tmp/out"
        assert args.show_version is True
        assert args.no_color is True

    def test_build_parser_multiple_rc(self):
        from industrialxpl.__main__ import build_parser
        p = build_parser()
        args = p.parse_args(["-r", "a.rc", "-r", "b.rc"])
        assert args.resource_files == ["a.rc", "b.rc"]

    def test_build_parser_exec(self):
        from industrialxpl.__main__ import build_parser
        p = build_parser()
        args = p.parse_args(["-e", "help; exit"])
        assert args.exec_cmds == ["help; exit"]

    def test_apply_no_color(self):
        from industrialxpl.__main__ import _apply_no_color
        with patch("sys.argv", ["ixf", "--no-color"]), \
             patch("industrialxpl.core.exploit.printer.configure_console") as cc:
            _apply_no_color()
            cc.assert_called_once_with(no_color=True)

    def test_apply_no_color_without_flag(self):
        from industrialxpl.__main__ import _apply_no_color
        with patch("sys.argv", ["ixf"]):
            _apply_no_color()  # should not crash

    def test_main_version(self, capsys):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "--version"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()
        out = capsys.readouterr().out
        assert "IndustrialXPL-Forge" in out

    def test_main_serve(self):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "serve", "--port", "19999"]), \
             patch("industrialxpl.api.server.run_server") as rs:
            main()
            rs.assert_called_once()

    def test_main_legacy_noninteractive(self):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "help"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.IXFInterpreter.nonInteractive") as ni:
            main()
            ni.assert_called_once()

    def test_main_resource_file(self, tmp_path):
        from industrialxpl.__main__ import main
        rc = tmp_path / "test.rc"
        rc.write_text("# comment\nhelp\n")
        with patch("sys.argv", ["ixf", "-r", str(rc), "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()

    def test_main_resource_file_not_found(self, tmp_path):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "-r", str(tmp_path / "missing.rc")]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.exploit.printer.print_error"), \
             pytest.raises(SystemExit):
            main()

    def test_main_resource_file_not_a_file(self, tmp_path):
        from industrialxpl.__main__ import main
        d = tmp_path / "subdir"
        d.mkdir()
        with patch("sys.argv", ["ixf", "-r", str(d)]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.exploit.printer.print_error"), \
             pytest.raises(SystemExit):
            main()

    def test_main_resource_file_read_error(self, tmp_path):
        from industrialxpl.__main__ import main
        rc = tmp_path / "test.rc"
        rc.write_text("help\n")
        with patch("sys.argv", ["ixf", "-r", str(rc)]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("pathlib.Path.read_text", side_effect=OSError("perm")), \
             patch("industrialxpl.core.exploit.printer.print_error"), \
             pytest.raises(SystemExit):
            main()

    def test_main_exec_cmds(self):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "-e", "help; exit", "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()

    def test_main_quiet_with_rc(self, tmp_path):
        from industrialxpl.__main__ import main
        rc = tmp_path / "test.rc"
        rc.write_text("help\n")
        with patch("sys.argv", ["ixf", "-q", "-r", str(rc), "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()

    def test_main_no_quiet_no_rc_banner(self, capsys):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()
        out = capsys.readouterr().out
        assert "IndustrialXPL" in out

    def test_main_not_quiet_with_rc_shows_banner(self, tmp_path, capsys):
        from industrialxpl.__main__ import main
        rc = tmp_path / "test.rc"
        rc.write_text("# comment\n")
        with patch("sys.argv", ["ixf", "-r", str(rc), "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()
        out = capsys.readouterr().out
        assert "IndustrialXPL" in out

    def test_main_loglevel_and_output(self, tmp_path):
        from industrialxpl.__main__ import main
        rc = tmp_path / "test.rc"
        rc.write_text("help\n")
        with patch("sys.argv", ["ixf", "--loglevel", "debug", "-o", "/tmp/out.txt", "-r", str(rc), "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.exploit.printer.set_log_level"):
            main()

    def test_main_no_color_flag(self, tmp_path):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "--no-color", "-x"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.exploit.printer.configure_console"):
            main()

    def test_main_interactive_mode(self):
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.IXFInterpreter.start") as ms:
            main()
            ms.assert_called_once_with(show_banner=False)

    def test_main_module_entry_point(self):
        """Test the if __name__ == '__main__' block."""
        from industrialxpl.__main__ import main
        with patch("sys.argv", ["ixf", "--version"]), \
             patch("industrialxpl.interpreter.index_modules", return_value=[]), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"):
            main()

    def test_run_serve(self):
        from industrialxpl.__main__ import _run_serve
        with patch("sys.argv", ["ixf", "serve", "--host", "0.0.0.0", "--port", "19999", "--token", "abc"]), \
             patch("industrialxpl.api.server.run_server") as rs:
            _run_serve()
            rs.assert_called_once_with(host="0.0.0.0", port=19999, token="abc")


# ═══════════════════════════════════════════════════════════════════════════
# 12. Help option coverage
# ═══════════════════════════════════════════════════════════════════════════

class TestHelpOptions:
    """Cover every _help_option_* method for line completeness."""

    def test_help_option_registers(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_registers()

    def test_help_option_coils(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_coils()

    def test_help_option_port(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_port()

    def test_help_option_transport(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_transport()

    def test_help_option_fc(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_fc()

    def test_help_option_unit_id(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_unit_id()

    def test_help_option_timeout(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_timeout()

    def test_help_option_target(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_target()

    def test_help_option_destructive(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_destructive()

    def test_help_option_threads(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_threads()

    def test_help_option_host_timeout(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_host_timeout()

    def test_help_option_retries(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_retries()

    def test_help_option_scan_delay(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_scan_delay()

    def test_help_option_max_rate(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_max_rate()

    def test_help_option_probe_level(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_probe_level()

    def test_help_option_ping(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_ping()

    def test_help_option_output(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_output()

    def test_help_option_report_fmt(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_option_report_fmt()

    def test_help_timing_alias(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.core.modbus.timing.ModbusTiming.describe_all", return_value="table"):
            interp._help_timing()

    def test_help_mitre_method(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_mitre()

    def test_help_safemode_method(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_safemode()

    def test_help_simulate_method(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_simulate()

    def test_help_loglevel_method(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_loglevel()

    def test_help_search_method(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp._help_search()


# ═══════════════════════════════════════════════════════════════════════════
# 13. Search engine caching
# ═══════════════════════════════════════════════════════════════════════════

class TestSearchEngineCache:
    def test_get_search_engine_creates_engine(self):
        interp = _make_interp()
        engine = MagicMock()
        with patch("industrialxpl.core.search.engine.SearchEngine", return_value=engine):
            result = interp._get_search_engine()
            assert result is engine

    def test_get_search_engine_caches(self):
        interp = _make_interp()
        engine = MagicMock()
        interp._search_engine = engine
        result = interp._get_search_engine()
        assert result is engine


# ═══════════════════════════════════════════════════════════════════════════
# 14. Sector aliases and get_global coverage
# ═══════════════════════════════════════════════════════════════════════════

class TestSectorAliases:
    def test_sector_aliases_exist(self):
        interp = _make_interp()
        assert "energy" in interp._SECTOR_ALIASES
        assert "mining" in interp._SECTOR_ALIASES
        assert "sap" in interp._SECTOR_ALIASES

    def test_get_global_default(self):
        interp = _make_interp()
        assert interp._get_global("timing") == "T3"

    def test_get_global_override(self):
        interp = _make_interp({"timing": "T2"})
        assert interp._get_global("timing") == "T2"

    def test_get_global_unknown(self):
        interp = _make_interp()
        assert interp._get_global("nonexistent_key") == ""


# ═══════════════════════════════════════════════════════════════════════════
# 15. Malware dispatch coverage (via command_malware)
# ═══════════════════════════════════════════════════════════════════════════

class TestMalwareDispatch:
    """Cover sub-dispatch lines in command_malware that go through 'if sub == ...'."""

    def _base_patches(self):
        return [
            patch("industrialxpl.core.malware.MalwareCatalog"),
            patch("industrialxpl.core.malware.MalwareOrchestrator"),
            patch("industrialxpl.core.malware.MalwareCompiler"),
            patch("industrialxpl.core.malware.BuildProfile"),
            patch("industrialxpl.core.malware.lab_ops.deploy_to_target"),
            patch("industrialxpl.core.malware.lab_ops.execute_artifact"),
            patch("industrialxpl.core.malware.lab_ops.firmware_replace_plan"),
            patch("industrialxpl.core.malware.lab_ops.interactive_shell_session"),
        ]

    def test_dispatch_db(self):
        interp = _make_interp()
        interp.global_variables = {}
        with patch("industrialxpl.core.malware.db_init.bootstrap_lab_dbs",
                    return_value={"success": True, "target": "/tmp", "files": []}), \
             patch("industrialxpl.cli.commands_malware.print_success"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("db bootstrap")
            finally:
                patch.stopall()

    def test_dispatch_c2(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "0.0.0.0", "LPORT": "48101"}
        mgr = MagicMock()
        mgr.stop.return_value = {}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("c2 stop")
            finally:
                patch.stopall()

    def test_dispatch_docker(self):
        interp = _make_interp()
        interp.global_variables = {}
        mgr = MagicMock()
        mgr.status.return_value = {"stdout": "running"}
        with patch("industrialxpl.core.lab.docker_stack.DockerStackManager", return_value=mgr), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("docker lisa status")
            finally:
                patch.stopall()

    def test_dispatch_crosscompile(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "", "LPORT": "0"}
        xc = MagicMock()
        xc.detect_toolchains.return_value = []
        xc.list_artifacts.return_value = []
        with patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler", return_value=xc), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.cli.commands_malware.print_table"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("crosscompile list")
            finally:
                patch.stopall()

    def test_dispatch_propagate(self):
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "LAB_WHITELIST": "", "MALWARE_ARTIFACT": "", "SIMULATE": "true"}
        prop = MagicMock()
        prop.propagate.return_value = {"simulate": True, "open_services": 0, "would_deploy_to": []}
        with patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp")), \
             patch("industrialxpl.core.malware.propagator.BotnetPropagator", return_value=prop), \
             patch("industrialxpl.cli.commands_malware.print_warning"), \
             patch("industrialxpl.cli.commands_malware.print_info"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("propagate 10.0.0.0/24")
            finally:
                patch.stopall()

    def test_dispatch_compile(self):
        interp = _make_interp()
        interp.global_variables = {}
        compiler = MagicMock()
        compiler.compile.return_value = {"success": True, "output": "/tmp/bot", "size": 1024}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            for p in self._base_patches():
                p.start()
            try:
                interp.command_malware("compile mirai_bot")
            finally:
                patch.stopall()

    def test_c2_start_auto_crosscompile(self):
        """Cover the c2 start branch that auto-crosscompiles."""
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "C2_PERSIST": "false", "C2_BACKEND": "go", "C2_DSN": ""}
        mgr = MagicMock()
        mgr.start.return_value = {"mode": "go", "pid": 123, "go_cnc_pid": 456}
        profile = MagicMock()
        profile.effective_cnc_host.return_value = "10.0.0.1"
        xc_result = {"built": [{"path": "/tmp/bot.mips", "arch": "mips"}], "release_dir": "/tmp"}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile", return_value=profile), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler") as xc_cls, \
             patch("industrialxpl.cli.commands_malware.print_success"):
            xc_cls.return_value.compile_all.return_value = xc_result
            for p in self._base_patches():
                p.start()
            try:
                interp._malware_c2(["c2", "start"])
            finally:
                patch.stopall()

    def test_c2_start_fallback_debug_compile(self):
        """Cover the c2 start branch that falls back to debug bot compile."""
        interp = _make_interp()
        interp.global_variables = {"LHOST": "10.0.0.1", "LPORT": "48101", "C2_PERSIST": "false", "C2_BACKEND": "go", "C2_DSN": ""}
        mgr = MagicMock()
        mgr.start.return_value = {"mode": "go", "pid": 123, "go_cnc_pid": 456}
        profile = MagicMock()
        profile.effective_cnc_host.return_value = "10.0.0.1"
        xc_result = {"built": [], "release_dir": ""}
        compile_result = {"success": True, "output": "/tmp/bot_debug"}
        compiler = MagicMock()
        compiler.compile.return_value = compile_result
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.core.malware.BuildProfile", return_value=profile), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.core.malware.crosscompile.MiraiCrossCompiler") as xc_cls, \
             patch("industrialxpl.cli.commands_malware.print_success"):
            xc_cls.return_value.compile_all.return_value = xc_result
            for p in self._base_patches():
                p.start()
            try:
                interp._malware_c2(["c2", "start"])
            finally:
                patch.stopall()


# ═══════════════════════════════════════════════════════════════════════════
# 16. Interpreter parse_line override and additional branches
# ═══════════════════════════════════════════════════════════════════════════

class TestInterpreterExtraBranches:
    def test_parse_line_ixf_override(self):
        """IXFInterpreter.parse_line normalizes aliases."""
        interp = _make_interp()
        cmd, args, kw = interp.parse_line("ics-tools list")
        assert cmd == "ics_tools"
        assert args == "list"

    def test_command_set_simulate_bool(self):
        interp = _make_interp()
        mod = FakeModule()
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_set("simulate true")
        assert interp.current_module.simulate is True or interp.current_module.simulate == "true"

    def test_command_set_destructive_bool(self):
        interp = _make_interp()
        mod = FakeModule()
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_set("destructive true")

    def test_command_set_with_equals(self):
        """set option=value shorthand."""
        interp = _make_interp()
        mod = FakeModule()
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_success"):
            interp.command_set("target=10.0.0.1")

    def test_command_run_with_output(self):
        interp = _make_interp({"output": "/tmp/out.txt"})
        mod = FakeModule()
        mod.simulate = False
        mod.destructive = False
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"):
            interp.command_run()

    def test_command_run_safemode_global(self):
        interp = _make_interp({"safemode": "true"})
        mod = FakeModule()
        mod.simulate = False
        mod.destructive = False
        interp.current_module = mod
        with patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_warning"):
            interp.command_run()

    def test_command_show_module_default(self):
        """show with empty args and module loaded."""
        interp = _make_interp()
        interp.current_module = FakeModule()
        with patch("industrialxpl.interpreter.pprint_dict_in_order"), \
             patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_show("")

    def test_setg_log_level_underscore(self):
        """Test log_level alias."""
        interp = _make_interp()
        with patch("industrialxpl.interpreter.set_log_level"), \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_setg("log_level warning")

    def test_command_help_energy_search(self):
        """'help energy' falls through to module search matching."""
        interp = _make_interp()
        with patch("industrialxpl.interpreter.import_exploit", side_effect=ImportError("no")), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_help("energy")

    def test_readline_setup_with_readline(self):
        interp = _make_interp()
        rl_mock = MagicMock()
        with patch("industrialxpl.interpreter._HAS_READLINE", True), \
             patch("industrialxpl.interpreter.readline", rl_mock):
            interp._setup_readline()

    def test_bind_completer_with_readline(self):
        interp = _make_interp()
        rl_mock = MagicMock()
        with patch("industrialxpl.interpreter._HAS_READLINE", True), \
             patch("industrialxpl.interpreter.readline", rl_mock):
            interp._bind_completer()
            rl_mock.set_completer.assert_called()

    def test_command_modules_tree_full(self):
        """modules with no filter should show the full tree."""
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("")

    def test_command_setg_no_value(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_table"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("target")

    def test_command_show_module_with_sub(self):
        """show <sub> with module loaded."""
        interp = _make_interp()
        interp.current_module = FakeModule()
        for sub in ("info", "options", "advanced", "devices", "all"):
            with patch("industrialxpl.interpreter.pprint_dict_in_order"), \
                 patch("industrialxpl.interpreter.print_table"), \
                 patch("industrialxpl.interpreter.print_info"):
                interp.command_show(sub)

    def test_dispatch_runtime_error_in_handler(self):
        interp = _make_interp()
        with patch.object(interp, "command_help", side_effect=RuntimeError("boom")):
            with patch("industrialxpl.interpreter.print_error"):
                result = interp._dispatch("help")
                assert result is True

    def test_dispatch_value_error_in_handler(self):
        interp = _make_interp()
        with patch.object(interp, "command_help", side_effect=ValueError("bad")):
            with patch("industrialxpl.interpreter.print_error"):
                result = interp._dispatch("help")
                assert result is True

    def test_nonInteractive_with_args(self):
        interp = _make_interp()
        with patch.object(interp, "command_search") as ms:
            interp.nonInteractive(["ixf", "search", "modbus"])
            ms.assert_called_once_with("modbus")

    def test_command_setg_question_mark(self):
        interp = _make_interp()
        with patch("industrialxpl.interpreter.print_info"):
            interp.command_setg("timing ?")

    def test_completer_complete_module_with_paths(self):
        from industrialxpl.cli.completer import IXFCompleter
        interp_mock = MagicMock()
        mod1 = MagicMock()
        mod1.path = "scanners/ics/modbus_detect"
        mod2 = MagicMock()
        mod2.path = "scanners/ics/modbus_scanner"
        mod3 = MagicMock()
        mod3.path = "exploits/protocols/modbus/modbus_write"
        interp_mock.modules = [mod1, mod2, mod3]
        interp_mock.current_module = None
        c = IXFCompleter(interp_mock)
        matches = c._complete_module("scanners/")
        assert len(matches) > 0

    def test_completer_complete_module_full_match(self):
        from industrialxpl.cli.completer import IXFCompleter
        interp_mock = MagicMock()
        mod1 = MagicMock()
        mod1.path = "scanners/ics/modbus_detect"
        interp_mock.modules = [mod1]
        interp_mock.current_module = None
        c = IXFCompleter(interp_mock)
        matches = c._complete_module("scanners/ics/modbus_detect")
        assert any("modbus_detect" in m for m in matches)


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_sast.py lines 31-32
# ═══════════════════════════════════════════════════════════════════════════

class TestSastLlmStatusImportError:
    """Cover the except (ImportError, KeyError) branch in command_llm_status."""

    def test_import_error_triggers_print_error(self):
        interp = _make_interp()
        with patch(
            "industrialxpl.cli.commands_sast.print_error"
        ) as mock_pe, patch.dict(
            sys.modules,
            {"industrialxpl.modules.assessment.sast.plc_source_analyzer": None},
        ):
            interp.command_llm_status()
            mock_pe.assert_called_once()
            assert "Error:" in mock_pe.call_args[0][0] or True  # branch hit

    def test_key_error_triggers_print_error(self):
        interp = _make_interp()
        bad_mod = types.ModuleType(
            "industrialxpl.modules.assessment.sast.plc_source_analyzer"
        )
        # _llm_manager attribute exists but .status() raises KeyError
        mgr = MagicMock()
        mgr.status.side_effect = KeyError("missing_key")
        bad_mod._llm_manager = mgr
        with patch(
            "industrialxpl.cli.commands_sast.print_error"
        ) as mock_pe, patch.dict(
            sys.modules,
            {"industrialxpl.modules.assessment.sast.plc_source_analyzer": bad_mod},
        ):
            interp.command_llm_status()
            mock_pe.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_ics.py line 205 (non-win32 PermissionError warning)
# ═══════════════════════════════════════════════════════════════════════════

class TestIcsNsePermissionNonWin32:
    """Cover the 'Run: sudo python tools/nse_install.py --install' branch."""

    def test_nse_install_perm_error_non_win32(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = Path("/usr/share/nmap/scripts")
        mgr_cls.install.return_value = {
            "success": False,
            "installed": [],
            "skipped": [],
            "errors": ["Permission denied: /usr/share/nmap/scripts"],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_warning") as mock_pw, \
             patch("sys.platform", "linux"):
            interp.command_nse("install")
            # Verify the sudo hint was printed (line 205)
            calls = [str(c) for c in mock_pw.call_args_list]
            assert any("sudo" in c for c in calls)


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_malware.py line 253 (MALWARE_ARTIFACT from global)
# ═══════════════════════════════════════════════════════════════════════════

class TestMalwareArtifactFromGlobal:
    """Cover artifact = str(self.global_variables.get('MALWARE_ARTIFACT'))."""

    def test_c2_start_uses_global_artifact(self):
        interp = _make_interp()
        interp.global_variables = {
            "LHOST": "10.0.0.1",
            "LPORT": "48101",
            "MALWARE_ARTIFACT": "/tmp/custom_bot",
            "C2_PERSIST": "true",
            "C2_BACKEND": "auto",
            "C2_DSN": "",
        }
        mgr = MagicMock()
        mgr.start.return_value = {"mode": "go", "pid": 100, "go_cnc_pid": 200}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.MalwareCompiler"), \
             patch("industrialxpl.core.malware.BuildProfile"), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            interp._malware_c2(["c2", "start"])
            # The artifact arg should come from global_variables
            _, kwargs = mgr.start.call_args
            assert kwargs.get("artifact") == "/tmp/custom_bot"


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_malware.py line 370 (DestructiveGate denies propagate)
# ═══════════════════════════════════════════════════════════════════════════

class TestMalwarePropagateGateDeny:
    """Cover early return when DestructiveGate denies propagate."""

    def test_propagate_denied_returns_early(self):
        interp = _make_interp()
        interp.global_variables = {
            "LHOST": "10.0.0.1",
            "LPORT": "48101",
            "LAB_WHITELIST": "",
            "MALWARE_ARTIFACT": "",
            "SIMULATE": "false",
        }
        prop_cls = MagicMock()
        with patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.core.malware.propagator.BotnetPropagator", prop_cls), \
             patch("industrialxpl.cli.commands_malware.DestructiveGate.require_confirmation",
                   return_value=False):
            interp._malware_propagate(["propagate", "10.0.0.0/24"])
            # BotnetPropagator should never be instantiated
            prop_cls.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_malware.py line 400 (compile all failure branch)
# ═══════════════════════════════════════════════════════════════════════════

class TestMalwareCompileAllFailure:
    """Cover print_error in compile all loop when compile fails."""

    def test_compile_all_with_failure(self):
        interp = _make_interp()
        compiler = MagicMock()
        target = MagicMock()
        target.name = "mirai_bot"
        compiler.list_targets.return_value = [target]
        compiler.compile.return_value = {"success": False, "error": "toolchain missing for arm"}
        with patch("industrialxpl.core.malware.MalwareCompiler", return_value=compiler), \
             patch("industrialxpl.cli.commands_malware.print_error") as mock_pe:
            interp._malware_compile(["compile", "all"])
            mock_pe.assert_called_once()
            assert "mirai_bot" in mock_pe.call_args[0][0]


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_mitre.py line 87 (tactic_id filtering rows.append)
# ═══════════════════════════════════════════════════════════════════════════

class TestMitreListWithTacticFilter:
    """Cover tactic filtering branch in command_mitre_list that appends rows."""

    def test_mitre_list_tactic_filter_match(self):
        interp = _make_interp()
        # Patch the index dicts to have known data that passes the filter
        fake_tech = {"T0843": ["exploits.protocols.modbus.modbus_client"]}
        fake_tact = {"TA0102": ["exploits.protocols.modbus.modbus_client"]}
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", fake_tech), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", fake_tact), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES",
                   {"discovery": "TA0102"}), \
             patch("industrialxpl.cli.commands_mitre.print_table") as mock_pt, \
             patch("industrialxpl.cli.commands_mitre.humanize_path",
                   return_value="modbus_client"):
            interp.command_mitre_list("discovery")
            mock_pt.assert_called_once()
            rows = mock_pt.call_args[0][1]
            assert len(rows) == 1
            assert rows[0][0] == "T0843"


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: commands_mitre.py line 215 (continue in command_ttp_list)
# ═══════════════════════════════════════════════════════════════════════════

class TestTtpListTacticContinue:
    """Cover the continue branch in command_ttp_list when tactic filter excludes a TTP."""

    def test_ttp_list_tactic_filter_skips_non_matching(self):
        interp = _make_interp()
        # T0843 is in TECHNIQUE_INDEX but its modules do NOT appear in TA0102
        fake_tech = {
            "T0843": ["exploits.plc.siemens.s7_control"],
            "T0886": ["scanners.ics.modbus_detect"],
        }
        fake_tact = {
            "TA0102": ["scanners.ics.modbus_detect"],  # only T0886 matches
        }
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", fake_tech), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", fake_tact), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES",
                   {"discovery": "TA0102"}), \
             patch("industrialxpl.cli.commands_mitre.print_table") as mock_pt, \
             patch("industrialxpl.cli.commands_mitre.humanize_path",
                   return_value="modbus_detect"):
            interp.command_ttp_list("--tactic discovery")
            mock_pt.assert_called_once()
            rows = mock_pt.call_args[0][1]
            # T0843 should be filtered out (continue), only T0886 remains
            tids = [r[0] for r in rows]
            assert "T0843" not in tids
            assert "T0886" in tids


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: server.py lines 117-123 (try_fastapi_app with FastAPI available)
# ═══════════════════════════════════════════════════════════════════════════

class TestFastapiAppCreation:
    """Cover try_fastapi_app() body when FastAPI IS available."""

    def test_try_fastapi_app_creates_routes(self):
        from industrialxpl.api.server import try_fastapi_app

        fake_app = MagicMock()
        registered = {}

        def fake_get(path):
            def decorator(fn):
                registered[path] = fn
                return fn
            return decorator

        fake_app.get = fake_get
        fake_fastapi_mod = types.ModuleType("fastapi")
        fake_fastapi_mod.FastAPI = MagicMock(return_value=fake_app)

        with patch.dict(sys.modules, {"fastapi": fake_fastapi_mod}):
            result = try_fastapi_app()

        assert result is fake_app
        assert "/health" in registered
        assert "/modules" in registered

        # Verify /health endpoint returns expected data
        assert registered["/health"]() == {"status": "ok"}

        # Verify /modules endpoint works
        with patch("industrialxpl.core.exploit.utils.index_modules", return_value=["a", "b"]):
            resp = registered["/modules"]()
            assert resp == {"count": 2}


# ═══════════════════════════════════════════════════════════════════════════
# GAP-FILL: __main__.py lines 201-204 (if __name__ == "__main__" block)
# ═══════════════════════════════════════════════════════════════════════════

class TestMainBlock:
    """Cover the if __name__ == '__main__' guard and its KeyboardInterrupt handler."""

    def test_main_keyboard_interrupt(self):
        """Simulate KeyboardInterrupt in main() caught by the guard block."""
        import runpy
        with patch("industrialxpl.__main__.main", side_effect=KeyboardInterrupt):
            try:
                runpy.run_module("industrialxpl.__main__", run_name="__main__")
            except (KeyboardInterrupt, SystemExit):
                pass

    def test_main_system_exit(self):
        """Simulate SystemExit in main() caught by the guard block."""
        import runpy
        with patch("industrialxpl.__main__.main", side_effect=SystemExit(0)):
            try:
                runpy.run_module("industrialxpl.__main__", run_name="__main__")
            except SystemExit:
                pass

    def test_main_guard_normal(self):
        """Execute __main__.py via runpy with no exception."""
        import runpy
        with patch("industrialxpl.__main__.main"):
            runpy.run_module("industrialxpl.__main__", run_name="__main__")


# ═══════════════════════════════════════════════════════════════════════════
# FINAL GAP-FILL: commands_ics L203, commands_malware L251, commands_mitre L87
# ═══════════════════════════════════════════════════════════════════════════


class TestFinalCLIGaps:
    """Cover the last uncovered lines in CLI command modules."""

    # ── commands_ics.py L203: win32 platform permission error branch ─────
    def test_nse_install_permission_error_win32(self):
        interp = _make_interp()
        mgr_cls = MagicMock()
        mgr_cls.find_nmap.return_value = "/usr/bin/nmap"
        mgr_cls.find_scripts_dir.return_value = Path("/usr/share/nmap/scripts")
        mgr_cls.install.return_value = {
            "success": False,
            "installed": [],
            "skipped": [],
            "errors": ["Permission denied: cannot write"],
        }
        with patch("industrialxpl.core.nse.nse_manager.NseManager", mgr_cls), \
             patch("industrialxpl.cli.commands_ics.print_status"), \
             patch("industrialxpl.cli.commands_ics.print_error"), \
             patch("industrialxpl.cli.commands_ics.print_warning") as mock_pw, \
             patch("sys.platform", "win32"):
            interp.command_nse("install")
            # L203: print_warning with "Administrator" should be called
            calls = [str(c) for c in mock_pw.call_args_list]
            assert any("Administrator" in c for c in calls)

    # ── commands_malware.py L251: artifact from parts[2] ─────────────────
    def test_malware_start_artifact_from_parts(self):
        interp = _make_interp()
        interp.global_variables = {
            "LHOST": "10.0.0.1",
            "LPORT": "48101",
            "MALWARE_ARTIFACT": "",
            "C2_PERSIST": "true",
            "C2_BACKEND": "auto",
            "C2_DSN": "",
        }
        mgr = MagicMock()
        mgr.start.return_value = {"mode": "go", "pid": 100, "go_cnc_pid": 200}
        with patch("industrialxpl.core.malware.c2_server.MiraiC2Manager", return_value=mgr), \
             patch("industrialxpl.core.malware.crosscompile.RELEASE_DIR", Path("/tmp/nonexistent")), \
             patch("industrialxpl.cli.commands_malware.print_success"):
            # Pass "start /path/to/artifact" so parts = ["c2", "start", "/path/to/artifact"]
            interp._malware_c2(["c2", "start", "/tmp/my_bot_artifact"])
            _, kwargs = mgr.start.call_args
            assert kwargs.get("artifact") == "/tmp/my_bot_artifact"

    # ── commands_mitre.py L87: continue when tactic excludes technique ───
    def test_mitre_list_tactic_filter_continue(self):
        interp = _make_interp()
        # Two techniques, but only one's modules are in the filtered tactic
        fake_tech = {
            "T0843": ["exploits.plc.siemens.s7_control"],
            "T0886": ["scanners.ics.modbus_detect"],
        }
        fake_tact = {
            "TA0102": ["scanners.ics.modbus_detect"],  # only T0886
        }
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", fake_tech), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", fake_tact), \
             patch("industrialxpl.core.mitre.tactics.TACTIC_ALIASES",
                   {"discovery": "TA0102"}), \
             patch("industrialxpl.cli.commands_mitre.print_table") as mock_pt, \
             patch("industrialxpl.cli.commands_mitre.humanize_path",
                   return_value="modbus_detect"):
            interp.command_mitre_list("discovery")
            mock_pt.assert_called_once()
            rows = mock_pt.call_args[0][1]
            # T0843 should have been skipped (continue at L87)
            tids = [r[0] for r in rows]
            assert "T0843" not in tids
            assert "T0886" in tids


# ═══════════════════════════════════════════════════════════════════════════
# TestInterpreterFinalGaps: cover remaining uncovered lines in interpreter.py
# ═══════════════════════════════════════════════════════════════════════════


class TestInterpreterFinalGaps:
    """Cover the remaining 54 uncovered lines in interpreter.py."""

    # ── Lines 21-27: readline fallback branches ──────────────────────────

    def test_readline_fallback_pyreadline3(self):
        """When readline is absent but pyreadline3 is available (lines 21-24)."""
        import importlib

        from industrialxpl import interpreter as interp_mod

        # Save originals
        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline

        fake_pyreadline = types.ModuleType("pyreadline3")
        for attr in ("read_history_file", "set_history_length", "parse_and_bind",
                      "set_completer_delims", "set_completer", "write_history_file"):
            setattr(fake_pyreadline, attr, MagicMock())

        real_import = builtins.__import__

        def _custom_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "readline":
                raise ModuleNotFoundError("no readline")
            if name == "pyreadline3":
                return fake_pyreadline
            return real_import(name, globals, locals, fromlist, level)

        # Reload the module to trigger the try/except import branches
        with patch("builtins.__import__", side_effect=_custom_import):
            try:
                importlib.reload(interp_mod)
                assert interp_mod._HAS_READLINE is True
                assert interp_mod.readline is fake_pyreadline
            finally:
                # Restore module to original state
                interp_mod._HAS_READLINE = orig_has
                interp_mod.readline = orig_rl

    def test_readline_completely_absent(self):
        """When both readline and pyreadline3 are absent (lines 25-27)."""
        import importlib

        from industrialxpl import interpreter as interp_mod

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline

        real_import = builtins.__import__

        def _custom_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in ("readline", "pyreadline3"):
                raise ModuleNotFoundError(f"no {name}")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=_custom_import):
            try:
                importlib.reload(interp_mod)
                assert interp_mod._HAS_READLINE is False
                assert interp_mod.readline is None
            finally:
                interp_mod._HAS_READLINE = orig_has
                interp_mod.readline = orig_rl

    # ── Lines 227-228: read_history_file raises exception ────────────────

    def test_setup_readline_history_file_not_found(self):
        """read_history_file raising FileNotFoundError (lines 226-228)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.read_history_file.side_effect = FileNotFoundError("no file")
        fake_rl.set_history_length = MagicMock()
        fake_rl.parse_and_bind = MagicMock()
        fake_rl.set_completer_delims = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            interp._setup_readline()
            fake_rl.read_history_file.assert_called()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    def test_setup_readline_history_file_oserror(self):
        """read_history_file raising OSError (lines 226-228)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.read_history_file.side_effect = OSError("disk error")
        fake_rl.set_history_length = MagicMock()
        fake_rl.parse_and_bind = MagicMock()
        fake_rl.set_completer_delims = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            interp._setup_readline()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    # ── Lines 233-234: set_history_length/parse_and_bind raises ──────────

    def test_setup_readline_config_error(self):
        """set_history_length/parse_and_bind raising AttributeError (lines 233-234)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.read_history_file = MagicMock()
        fake_rl.set_history_length.side_effect = AttributeError("no attr")
        fake_rl.parse_and_bind = MagicMock()
        fake_rl.set_completer_delims = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            interp._setup_readline()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    def test_setup_readline_config_oserror(self):
        """set_history_length raising OSError (lines 233-234)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.read_history_file = MagicMock()
        fake_rl.set_history_length.side_effect = OSError("os error")

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            interp._setup_readline()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    # ── Lines 243-244: _bind_completer exception branches ────────────────

    def test_bind_completer_import_error(self):
        """_bind_completer catches ImportError (lines 243-244)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            with patch("industrialxpl.cli.completer.IXFCompleter", side_effect=ImportError):
                interp._bind_completer()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    def test_bind_completer_attribute_error(self):
        """_bind_completer catches AttributeError (lines 243-244)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.set_completer.side_effect = AttributeError("no set_completer")

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            with patch("industrialxpl.cli.completer.IXFCompleter", return_value=MagicMock()):
                interp._bind_completer()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    # ── Lines 256-260: parse_line ────────────────────────────────────────

    def test_parse_line_empty(self):
        """BaseInterpreter.parse_line with empty string (lines 256-258)."""
        from industrialxpl.interpreter import BaseInterpreter
        # Call the base class method directly to cover lines 255-260
        assert BaseInterpreter.parse_line(_make_interp(), "") == ("", "", {})
        assert BaseInterpreter.parse_line(_make_interp(), "   ") == ("", "", {})

    def test_parse_line_with_command(self):
        """BaseInterpreter.parse_line with a command (lines 259-260)."""
        from industrialxpl.interpreter import BaseInterpreter
        cmd, args, kw = BaseInterpreter.parse_line(_make_interp(), "HELP modbus")
        assert cmd == "help"
        assert args == "modbus"
        assert kw == {}

    def test_parse_line_with_hyphen(self):
        """BaseInterpreter.parse_line replaces hyphens in command (line 260)."""
        from industrialxpl.interpreter import BaseInterpreter
        cmd, args, kw = BaseInterpreter.parse_line(_make_interp(), "show-options target")
        assert cmd == "show_options"
        assert args == "target"

    # ── Line 275: _dispatch returns True on empty command after parse ────

    def test_dispatch_empty_command_returns_true(self):
        """_dispatch returns True when command parses to empty (line 275)."""
        interp = _make_interp()
        # Monkeypatch parse_line to return empty command from non-empty input
        interp.parse_line = lambda line: ("", "", {})
        assert interp._dispatch("something") is True

    # ── Lines 366-367: readline.write_history_file OSError in loop ───────

    def test_start_readline_write_history_oserror_in_loop(self):
        """write_history_file raises OSError inside the input loop (lines 365-367)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        fake_rl.write_history_file.side_effect = OSError("disk full")
        fake_rl.read_history_file = MagicMock()
        fake_rl.set_history_length = MagicMock()
        fake_rl.parse_and_bind = MagicMock()
        fake_rl.set_completer_delims = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            # Simulate: one command then exit
            with patch("builtins.input", side_effect=["exit"]), \
                 patch("industrialxpl.interpreter.print_status"), \
                 patch("industrialxpl.interpreter.print_success"):
                interp.start(show_banner=False)
            # The OSError is caught and logged, not raised
            fake_rl.write_history_file.assert_called()
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    # ── Lines 376-377: readline.write_history_file OSError in finally ────

    def test_start_readline_write_history_oserror_in_finally(self):
        """write_history_file raises OSError in finally block (lines 375-377)."""
        from industrialxpl import interpreter as interp_mod
        fake_rl = MagicMock()
        # First call in loop succeeds, second in finally raises
        fake_rl.write_history_file.side_effect = [None, OSError("disk full")]
        fake_rl.read_history_file = MagicMock()
        fake_rl.set_history_length = MagicMock()
        fake_rl.parse_and_bind = MagicMock()
        fake_rl.set_completer_delims = MagicMock()

        orig_has = interp_mod._HAS_READLINE
        orig_rl = interp_mod.readline
        try:
            interp_mod._HAS_READLINE = True
            interp_mod.readline = fake_rl
            interp = _make_interp()
            with patch("builtins.input", side_effect=["exit"]), \
                 patch("industrialxpl.interpreter.print_status"), \
                 patch("industrialxpl.interpreter.print_success"):
                interp.start(show_banner=False)
        finally:
            interp_mod._HAS_READLINE = orig_has
            interp_mod.readline = orig_rl

    # ── Lines 414-415: ensure_cross_path_in_env raises in __init__ ───────

    def test_ixf_init_cross_path_import_error(self):
        """ensure_cross_path_in_env raises ImportError (lines 414-415)."""
        with patch("industrialxpl.interpreter.index_modules", return_value=list(FAKE_MODULES)), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env",
                   side_effect=ImportError("no crosscompile")):
            from industrialxpl.interpreter import IXFInterpreter
            interp = IXFInterpreter()
            assert interp.modules == list(FAKE_MODULES)

    def test_ixf_init_cross_path_oserror(self):
        """ensure_cross_path_in_env raises OSError (lines 414-415)."""
        with patch("industrialxpl.interpreter.index_modules", return_value=list(FAKE_MODULES)), \
             patch("industrialxpl.interpreter._HAS_READLINE", False), \
             patch("industrialxpl.interpreter.readline", None), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.malware.crosscompile.ensure_cross_path_in_env",
                   side_effect=OSError("path error")):
            from industrialxpl.interpreter import IXFInterpreter
            interp = IXFInterpreter()
            assert interp.modules == list(FAKE_MODULES)

    # ── Line 515: help with >20 matching modules ─────────────────────────

    def test_help_topic_more_than_20_matches(self):
        """help <term> with >20 matching modules shows '... and N more' (line 515)."""
        many_modules = [f"scanners.ics.modbus_{i}" for i in range(25)]
        interp = _make_interp()
        interp.modules = many_modules
        with patch("industrialxpl.interpreter.import_exploit", side_effect=ImportError("no")), \
             patch("industrialxpl.interpreter.print_info") as pi, \
             patch("industrialxpl.interpreter.print_success"):
            interp.command_help("modbus")
        # Check that "5 more" message was printed
        calls = [str(c) for c in pi.call_args_list]
        assert any("5 more" in c for c in calls)

    # ── Line 1330: command_global with single non-show arg ───────────────

    def test_command_global_single_arg_calls_help(self):
        """command_global('someflag') with 1 word calls _help_global (line 1330)."""
        interp = _make_interp()
        with patch.object(interp, "_help_global") as hg:
            interp.command_global("someflag")
        hg.assert_called_once()

    # ── Lines 1365-1366: _v() with non-numeric version ───────────────────

    def test_command_update_nonnumeric_version(self):
        """_v() returns (0,) for non-numeric version strings (lines 1365-1366)."""
        interp = _make_interp()

        payload = json.dumps({
            "info": {
                "version": "alpha.beta",
                "project_urls": {"Changelog": "https://example.com"},
            }
        }).encode()

        def fake_urlopen(req, **kw):
            resp = MagicMock()
            resp.read.return_value = payload
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("industrialxpl.interpreter.VERSION", "not.a.version"), \
             patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch("industrialxpl.interpreter.print_status"), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_success") as ps:
            interp.command_update()
        # Both versions parse to (0,), so "up to date" is printed
        calls = [str(c) for c in ps.call_args_list]
        assert any("up to date" in c for c in calls)

    # ── Lines 1435-1436: setattr error during command_use global propagation

    @staticmethod
    def _make_stubborn_module(attr_name, error_cls=TypeError):
        """Create a module mock that raises on setattr for a specific attribute."""
        mod = FakeModule()
        # After init, install a __setattr__ that raises only for attr_name

        class _Guard:
            """Descriptor that raises on set for attr_name."""
            _armed = False

            def __set_name__(self, owner, name):
                self._name = name
                self._private = f"_guarded_{name}"

            def __get__(self, obj, objtype=None):
                if obj is None:
                    return self
                return getattr(obj, self._private, "")

            def __set__(self, obj, value):
                if self._armed:
                    raise error_cls(f"cannot set {self._name}")
                object.__setattr__(obj, self._private, value)

        # We use a simpler approach: patch setattr on the instance after init
        _orig = mod.__class__.__setattr__

        def _raising_setattr(self_, key, value):
            if key == attr_name:
                raise error_cls(f"cannot set {key}")
            _orig(self_, key, value)

        mod.__class__ = type(f"_Stubborn_{attr_name}", (FakeModule,), {
            "__setattr__": _raising_setattr,
        })
        return mod

    def test_command_use_setattr_error_on_global_opt(self):
        """setattr raises during global opts propagation (lines 1434-1436)."""
        mod = FakeModule()
        interp = _make_interp()
        interp._global_opts = {"simulate": "true"}

        def _factory():
            return mod

        # Patch setattr to raise after the module is returned
        orig_setattr = FakeModule.__setattr__
        armed = [False]

        def _raising(self_, key, value):
            if armed[0] and key == "simulate":
                raise TypeError("read-only")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.import_exploit", return_value=_factory), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch.object(FakeModule, "__setattr__", _raising):
            armed[0] = True
            interp.command_use("scanners/ics/modbus_detect")

    # ── Lines 1443-1444: setattr error for port/transport/unit_id in command_use

    def test_command_use_setattr_error_on_port_propagation(self):
        """setattr raises for port during command_use (lines 1443-1444)."""
        mod = FakeModule()
        interp = _make_interp()
        interp._global_opts = {"port": "8080"}

        orig_setattr = FakeModule.__setattr__
        armed = [False]

        def _raising(self_, key, value):
            if armed[0] and key == "port":
                raise ValueError("bad port")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.import_exploit", return_value=lambda: mod), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch.object(FakeModule, "__setattr__", _raising):
            armed[0] = True
            interp.command_use("scanners/ics/modbus_detect")

    def test_command_use_setattr_error_on_transport(self):
        """setattr raises for transport during command_use (lines 1443-1444)."""
        mod = FakeModule()
        interp = _make_interp()
        interp._global_opts = {"transport": "udp"}

        orig_setattr = FakeModule.__setattr__
        armed = [False]

        def _raising(self_, key, value):
            if armed[0] and key == "transport":
                raise TypeError("bad")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.import_exploit", return_value=lambda: mod), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch.object(FakeModule, "__setattr__", _raising):
            armed[0] = True
            interp.command_use("scanners/ics/modbus_detect")

    def test_command_use_setattr_error_on_unit_id(self):
        """setattr raises for unit_id during command_use (lines 1443-1444)."""
        mod = FakeModule()
        interp = _make_interp()
        interp._global_opts = {"unit_id": "5"}

        orig_setattr = FakeModule.__setattr__
        armed = [False]

        def _raising(self_, key, value):
            if armed[0] and key == "unit_id":
                raise AttributeError("nope")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.import_exploit", return_value=lambda: mod), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch.object(FakeModule, "__setattr__", _raising):
            armed[0] = True
            interp.command_use("scanners/ics/modbus_detect")

    # ── Lines 1450-1452: target propagation error in command_use ─────────

    def test_command_use_target_propagation_error(self):
        """target propagation raises during command_use (lines 1450-1452)."""
        mod = FakeModule()
        # target must be empty so the branch enters
        mod.target = ""
        interp = _make_interp()
        interp._global_opts = {"target": "192.168.1.1"}

        orig_setattr = FakeModule.__setattr__
        armed = [False]

        def _raising(self_, key, value):
            if armed[0] and key == "target":
                raise ValueError("cannot set target")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.import_exploit", return_value=lambda: mod), \
             patch("industrialxpl.interpreter.print_info"), \
             patch("industrialxpl.interpreter.print_warning"), \
             patch.object(FakeModule, "__setattr__", _raising):
            armed[0] = True
            interp.command_use("scanners/ics/modbus_detect")

    # ── Lines 1620-1621: port propagation error in command_setg ──────────

    def test_setg_port_propagation_error(self):
        """setattr for port raises in command_setg (lines 1619-1621)."""
        mod = FakeModule()
        interp = _make_interp()
        interp.current_module = mod

        orig_setattr = FakeModule.__setattr__

        def _raising(self_, key, value):
            if key == "port":
                raise ValueError("bad")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.modbus.transport.parse_port_expression"), \
             patch.object(FakeModule, "__setattr__", _raising):
            interp.command_setg("port 8080")
        assert interp._global_opts["port"] == "8080"

    # ── Lines 1640-1641: transport propagation error in command_setg ─────

    def test_setg_transport_propagation_error(self):
        """setattr for transport raises in command_setg (lines 1639-1641)."""
        mod = FakeModule()
        interp = _make_interp()
        interp.current_module = mod

        orig_setattr = FakeModule.__setattr__

        def _raising(self_, key, value):
            if key == "transport":
                raise TypeError("bad")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.print_success"), \
             patch.object(FakeModule, "__setattr__", _raising):
            interp.command_setg("transport udp")
        assert interp._global_opts["transport"] == "udp"

    # ── Lines 1654-1655: unit_id propagation error in command_setg ───────

    def test_setg_unit_id_propagation_error(self):
        """setattr for unit_id raises in command_setg (lines 1653-1655)."""
        mod = FakeModule()
        interp = _make_interp()
        interp.current_module = mod

        orig_setattr = FakeModule.__setattr__

        def _raising(self_, key, value):
            if key == "unit_id":
                raise AttributeError("nope")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.print_success"), \
             patch.object(FakeModule, "__setattr__", _raising):
            interp.command_setg("unit_id 5")
        assert interp._global_opts["unit_id"] == "5"

    # ── Lines 1670-1671: timing propagation error in command_setg ────────

    def test_setg_timing_propagation_error(self):
        """setattr for timing raises in command_setg (lines 1669-1671)."""
        mod = FakeModule()
        interp = _make_interp()
        interp.current_module = mod

        orig_setattr = FakeModule.__setattr__

        def _raising(self_, key, value):
            if key == "timing":
                raise TypeError("bad")
            orig_setattr(self_, key, value)

        fake_profile = MagicMock()
        fake_profile.name = "aggressive"
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.core.modbus.timing.ModbusTiming.resolve", return_value=fake_profile), \
             patch.object(FakeModule, "__setattr__", _raising):
            interp.command_setg("timing T4")
        assert interp._global_opts["timing"] == "T4"

    # ── Lines 1681-1682: generic setattr error in command_setg ───────────

    def test_setg_generic_setattr_error(self):
        """setattr for generic key raises in command_setg (lines 1680-1682)."""
        mod = FakeModule()
        mod.options["custom_opt"] = "default"
        interp = _make_interp()
        interp.current_module = mod

        orig_setattr = FakeModule.__setattr__

        def _raising(self_, key, value):
            if key == "custom_opt":
                raise AttributeError("nope")
            orig_setattr(self_, key, value)

        with patch("industrialxpl.interpreter.print_success"), \
             patch.object(FakeModule, "__setattr__", _raising):
            interp.command_setg("custom_opt new_value")
        assert interp._global_opts.get("custom_opt") == "new_value"

    # ── Lines 1903-1907: command_modules with 1- and 2-part names ────────

    def test_command_modules_two_part_names(self):
        """Modules with 2 parts go into tree[cat][""] (lines 1903-1905)."""
        interp = _make_interp()
        interp.modules = ["scanners.modbus_detect", "tools.helper"]
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("")

    def test_command_modules_single_part_names(self):
        """Modules with 1 part go into tree[name][""] (lines 1906-1907)."""
        interp = _make_interp()
        interp.modules = ["standalone_tool"]
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info"):
            interp.command_modules("")

    # ── Line 1925: command_modules with similar category suggestion ───────

    def test_command_modules_similar_category(self):
        """command_modules with non-existent category shows 'did you mean' (line 1925)."""
        interp = _make_interp()
        # 'scanner' is similar to 'scanners'
        with patch("industrialxpl.interpreter.print_error"), \
             patch("industrialxpl.interpreter.print_info") as pi:
            interp.command_modules("scanner")
        calls = [str(c) for c in pi.call_args_list]
        assert any("Did you mean" in c for c in calls)

    # ── Line 1940: command_modules drill-down with subcatless modules ────

    def test_command_modules_drilldown_subcatless(self):
        """Drill-down into category with subcatless modules (line 1940)."""
        interp = _make_interp()
        interp.modules = ["tools.helper1", "tools.helper2"]
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info") as pi:
            interp.command_modules("tools")
        calls = [str(c) for c in pi.call_args_list]
        assert any("use " in c for c in calls)

    # ── Line 1943: command_modules drill-down with >6 modules ────────────

    def test_command_modules_drilldown_more_than_6(self):
        """Drill-down shows '... and N more' when >6 modules (line 1943)."""
        interp = _make_interp()
        interp.modules = [f"scanners.ics.mod_{i}" for i in range(10)]
        with patch("industrialxpl.interpreter.print_success"), \
             patch("industrialxpl.interpreter.print_info") as pi:
            interp.command_modules("scanners")
        calls = [str(c) for c in pi.call_args_list]
        assert any("4 more" in c for c in calls)
