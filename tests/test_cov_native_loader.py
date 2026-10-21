"""Comprehensive unit tests for industrialxpl.core.native.loader (256 stmts).

Covers NativePayload dataclass, NativePayloadLoader class methods,
all execution paths (_exec_python, _exec_c, _exec_rust, _exec_go),
compiler discovery helpers, and the __init__.py re-exports.
"""

import importlib
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.core.native.loader import (
    _CONTRIB_RELATIVE,
    _PACKAGE_CONTRIB,
    _PROJECT_TMP,
    NativePayload,
    NativePayloadLoader,
)


def _make_payload(**overrides):
    defaults = dict(
        name="test-payload",
        slug="test-payload",
        directory=Path("/fake/contrib/test-payload"),
        language="python",
        entry_point="run",
        impact="CRITICAL",
        description="A test payload",
        mitre=["T1000"],
    )
    defaults.update(overrides)
    return NativePayload(**defaults)


@pytest.fixture(autouse=True)
def _reset_loader_state():
    NativePayloadLoader._registry = {}
    NativePayloadLoader._loaded = False
    yield
    NativePayloadLoader._registry = {}
    NativePayloadLoader._loaded = False


# === __init__.py re-exports ===

class TestNativeInit:
    def test_reexports(self):
        mod = importlib.import_module("industrialxpl.core.native")
        assert hasattr(mod, "NativePayload")
        assert hasattr(mod, "NativePayloadLoader")
        assert mod.NativePayload is NativePayload
        assert mod.NativePayloadLoader is NativePayloadLoader

    def test_all_exports(self):
        mod = importlib.import_module("industrialxpl.core.native")
        assert "NativePayload" in mod.__all__
        assert "NativePayloadLoader" in mod.__all__


# === NativePayload dataclass ===

class TestNativePayload:
    def test_fields(self):
        p = _make_payload()
        assert p.name == "test-payload"
        assert p.slug == "test-payload"
        assert p.language == "python"
        assert p.entry_point == "run"
        assert p.impact == "CRITICAL"
        assert p.description == "A test payload"
        assert p.mitre == ["T1000"]

    def test_mitre_default_empty(self):
        p = NativePayload(
            name="x", slug="x", directory=Path("/x"),
            language="python", entry_point="run",
            impact="CRITICAL", description="d",
        )
        assert p.mitre == []

    def test_source_path_payload_py(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "payload.py").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.py"
        assert p.available is True

    def test_source_path_payload_c(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "payload.c").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.c"

    def test_source_path_payload_rs(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.rs"

    def test_source_path_payload_go(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.go"

    def test_source_path_main_py(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "main.py").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "main.py"

    def test_source_path_main_c(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "main.c").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "main.c"

    def test_source_path_none_when_no_files(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        p = _make_payload(directory=d)
        assert p.source_path is None
        assert p.available is False

    def test_source_path_priority_order(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "main.py").touch()
        (d / "payload.py").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.py"

    def test_source_path_c_before_go(self, tmp_path):
        d = tmp_path / "mypayload"
        d.mkdir()
        (d / "payload.c").touch()
        (d / "payload.go").touch()
        p = _make_payload(directory=d)
        assert p.source_path == d / "payload.c"


# === NativePayloadLoader basics ===

class TestLoaderBasics:
    def test_contrib_dir(self):
        assert NativePayloadLoader.contrib_dir() == _PACKAGE_CONTRIB

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    def test_available_true(self, mock_contrib):
        mock_contrib.exists.return_value = True
        usage = MagicMock()
        usage.exists.return_value = True
        mock_contrib.__truediv__ = MagicMock(return_value=usage)
        assert NativePayloadLoader.available() is True

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    def test_available_false_no_dir(self, mock_contrib):
        mock_contrib.exists.return_value = False
        assert NativePayloadLoader.available() is False

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    def test_available_false_no_usage_md(self, mock_contrib):
        mock_contrib.exists.return_value = True
        usage = MagicMock()
        usage.exists.return_value = False
        mock_contrib.__truediv__ = MagicMock(return_value=usage)
        assert NativePayloadLoader.available() is False


# === _load_manifest ===

class TestLoadManifest:
    def test_skips_when_already_loaded(self):
        NativePayloadLoader._loaded = True
        NativePayloadLoader._load_manifest()
        assert NativePayloadLoader._registry == {}

    @patch.object(NativePayloadLoader, "available", return_value=False)
    def test_returns_when_not_available(self, _):
        NativePayloadLoader._load_manifest()
        assert NativePayloadLoader._loaded is True
        assert NativePayloadLoader._registry == {}

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_discovers_payloads(self, _, mock_contrib, tmp_path):
        pdir = tmp_path / "exploit1"
        pdir.mkdir()
        manifest = pdir / "manifest.py"
        manifest.write_text(
            "PAYLOAD_META = {\n"
            "    'name': 'Exploit One',\n"
            "    'language': 'python',\n"
            "    'entry_point': 'run',\n"
            "    'impact': 'CATASTROPHIC',\n"
            "    'description': 'Test exploit',\n"
            "    'mitre': ['T1234'],\n"
            "}\n"
        )
        (tmp_path / "README.md").touch()
        mock_contrib.iterdir.return_value = [pdir, tmp_path / "README.md"]
        NativePayloadLoader._load_manifest()
        assert "exploit1" in NativePayloadLoader._registry
        p = NativePayloadLoader._registry["exploit1"]
        assert p.name == "Exploit One"
        assert p.impact == "CATASTROPHIC"
        assert p.mitre == ["T1234"]

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_skips_dir_without_manifest(self, _, mock_contrib, tmp_path):
        pdir = tmp_path / "no_manifest"
        pdir.mkdir()
        mock_contrib.iterdir.return_value = [pdir]
        NativePayloadLoader._load_manifest()
        assert NativePayloadLoader._registry == {}

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_handles_broken_manifest_attribute_error(self, _, mock_contrib, tmp_path):
        """Manifest that triggers AttributeError is caught and skipped."""
        pdir = tmp_path / "broken"
        pdir.mkdir()
        (pdir / "manifest.py").touch()
        mock_contrib.iterdir.return_value = [pdir]
        with patch("importlib.util.spec_from_file_location", return_value=None):
            # spec is None, so spec.loader raises AttributeError
            NativePayloadLoader._load_manifest()
        assert "broken" not in NativePayloadLoader._registry

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_handles_broken_manifest_type_error(self, _, mock_contrib, tmp_path):
        """Manifest that triggers TypeError is caught and skipped."""
        pdir = tmp_path / "broken"
        pdir.mkdir()
        (pdir / "manifest.py").touch()
        mock_contrib.iterdir.return_value = [pdir]
        with patch("importlib.util.spec_from_file_location") as mock_sfl:
            fake_spec = MagicMock()
            fake_spec.loader.exec_module.side_effect = TypeError("bad type")
            mock_sfl.return_value = fake_spec
            NativePayloadLoader._load_manifest()
        assert "broken" not in NativePayloadLoader._registry

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_uncaught_exception_propagates(self, _, mock_contrib, tmp_path):
        """RuntimeError from manifest is NOT caught (narrow except clause)."""
        pdir = tmp_path / "broken"
        pdir.mkdir()
        (pdir / "manifest.py").touch()
        mock_contrib.iterdir.return_value = [pdir]
        with patch("importlib.util.spec_from_file_location") as mock_sfl:
            fake_spec = MagicMock()
            fake_spec.loader.exec_module.side_effect = RuntimeError("boom")
            mock_sfl.return_value = fake_spec
            with pytest.raises(RuntimeError, match="boom"):
                NativePayloadLoader._load_manifest()

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_no_payload_meta_attr(self, _, mock_contrib, tmp_path):
        pdir = tmp_path / "nopayload"
        pdir.mkdir()
        (pdir / "manifest.py").write_text("x = 42\n")
        mock_contrib.iterdir.return_value = [pdir]
        NativePayloadLoader._load_manifest()
        assert "nopayload" not in NativePayloadLoader._registry

    @patch("industrialxpl.core.native.loader._PACKAGE_CONTRIB")
    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_defaults(self, _, mock_contrib, tmp_path):
        pdir = tmp_path / "minimal"
        pdir.mkdir()
        (pdir / "manifest.py").write_text("PAYLOAD_META = {}\n")
        mock_contrib.iterdir.return_value = [pdir]
        NativePayloadLoader._load_manifest()
        p = NativePayloadLoader._registry["minimal"]
        assert p.name == "minimal"
        assert p.language == "python"
        assert p.entry_point == "run"
        assert p.impact == "CRITICAL"
        assert p.description == ""
        assert p.mitre == []


# === get / list_all ===

class TestGetAndListAll:
    def test_get_returns_payload(self):
        p = _make_payload(slug="myslug")
        NativePayloadLoader._registry["myslug"] = p
        NativePayloadLoader._loaded = True
        assert NativePayloadLoader.get("myslug") is p

    def test_get_returns_none(self):
        NativePayloadLoader._loaded = True
        assert NativePayloadLoader.get("nonexistent") is None

    def test_list_all(self):
        p1 = _make_payload(slug="a")
        p2 = _make_payload(slug="b")
        NativePayloadLoader._registry = {"a": p1, "b": p2}
        NativePayloadLoader._loaded = True
        result = NativePayloadLoader.list_all()
        assert len(result) == 2
        assert p1 in result and p2 in result

    def test_get_triggers_load(self):
        with patch.object(NativePayloadLoader, "_load_manifest") as m:
            NativePayloadLoader.get("x")
            m.assert_called_once()

    def test_list_all_triggers_load(self):
        with patch.object(NativePayloadLoader, "_load_manifest") as m:
            NativePayloadLoader.list_all()
            m.assert_called_once()


# === announce_if_available ===

class TestAnnounceIfAvailable:
    @patch.object(NativePayloadLoader, "available", return_value=False)
    def test_returns_false_when_not_available(self, _):
        assert NativePayloadLoader.announce_if_available("slug") is False

    @patch.object(NativePayloadLoader, "available", return_value=True)
    @patch.object(NativePayloadLoader, "get", return_value=None)
    def test_returns_false_when_no_payload(self, *_):
        assert NativePayloadLoader.announce_if_available("slug") is False

    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_returns_false_when_payload_not_available(self, _):
        p = _make_payload()
        with patch.object(type(p), "available", new_callable=PropertyMock, return_value=False):
            with patch.object(NativePayloadLoader, "get", return_value=p):
                assert NativePayloadLoader.announce_if_available("test-payload") is False

    @patch.object(NativePayloadLoader, "available", return_value=True)
    def test_returns_true_when_payload_available(self, _):
        p = _make_payload()
        with patch.object(type(p), "available", new_callable=PropertyMock, return_value=True):
            with patch.object(NativePayloadLoader, "get", return_value=p):
                assert NativePayloadLoader.announce_if_available("test-payload") is True


# === execute_native ===

class TestExecuteNative:
    def test_no_payload_registered(self):
        NativePayloadLoader._loaded = True
        assert NativePayloadLoader.execute_native("nope", "1.2.3.4", {}) is False

    def test_payload_source_not_found(self):
        p = _make_payload()
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(type(p), "available", new_callable=PropertyMock, return_value=False):
            assert NativePayloadLoader.execute_native("test-payload", "1.2.3.4", {}) is False

    def test_user_aborts(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.py").touch()
        p = _make_payload(directory=d)
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        confirm = MagicMock(return_value=False)
        result = NativePayloadLoader.execute_native(
            "test-payload", "1.2.3.4", {}, confirm_callback=confirm
        )
        assert result is False
        confirm.assert_called_once()

    def test_unsupported_language(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.py").touch()
        p = _make_payload(directory=d, language="brainfuck")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        result = NativePayloadLoader.execute_native(
            "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
        )
        assert result is False

    def test_dispatches_python(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.py").touch()
        p = _make_payload(directory=d, language="python")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_python", return_value=True) as m:
            result = NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {"a": 1}, confirm_callback=lambda: True
            )
            assert result is True
            m.assert_called_once_with(p, "1.2.3.4", {"a": 1})

    def test_dispatches_c(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").touch()
        p = _make_payload(directory=d, language="c")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_c", return_value=True) as m:
            result = NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
            )
            assert result is True
            m.assert_called_once()

    def test_dispatches_cpp(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").touch()
        p = _make_payload(directory=d, language="cpp")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_c", return_value=True) as m:
            NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
            )
            m.assert_called_once()

    def test_dispatches_cplusplus(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").touch()
        p = _make_payload(directory=d, language="c++")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_c", return_value=True) as m:
            NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
            )
            m.assert_called_once()

    def test_dispatches_rust(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_rust", return_value=True) as m:
            NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
            )
            m.assert_called_once()

    def test_dispatches_go(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_go", return_value=True) as m:
            NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=lambda: True
            )
            m.assert_called_once()

    def test_no_confirm_callback_proceeds(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.py").touch()
        p = _make_payload(directory=d, language="python")
        NativePayloadLoader._registry["test-payload"] = p
        NativePayloadLoader._loaded = True
        with patch.object(NativePayloadLoader, "_exec_python", return_value=True) as m:
            result = NativePayloadLoader.execute_native(
                "test-payload", "1.2.3.4", {}, confirm_callback=None
            )
            assert result is True
            m.assert_called_once()


# === _exec_python ===

class TestExecPython:
    def test_no_source(self):
        p = _make_payload()
        with patch.object(type(p), "source_path", new_callable=PropertyMock, return_value=None):
            assert NativePayloadLoader._exec_python(p, "1.2.3.4", {}) is False

    def test_successful_execution_truthy(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def run(target, options): return True\n")
        p = _make_payload(directory=d, entry_point="run")
        assert NativePayloadLoader._exec_python(p, "10.0.0.1", {"port": 502}) is True

    def test_successful_execution_falsy(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def run(target, options): return None\n")
        p = _make_payload(directory=d, entry_point="run")
        assert NativePayloadLoader._exec_python(p, "10.0.0.1", {}) is True

    def test_entry_point_not_found(self, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def other(): pass\n")
        p = _make_payload(directory=d, entry_point="run")
        assert NativePayloadLoader._exec_python(p, "10.0.0.1", {}) is False

    def test_attribute_error_caught(self, tmp_path):
        """AttributeError during execution is caught by the except clause."""
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def run(target, options): return True\n")
        p = _make_payload(directory=d, entry_point="run")
        with patch("importlib.util.spec_from_file_location", return_value=None):
            # spec is None; spec.loader raises AttributeError
            assert NativePayloadLoader._exec_python(p, "10.0.0.1", {}) is False

    def test_type_error_caught(self, tmp_path):
        """TypeError during execution is caught by the except clause."""
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def run(target, options): return True\n")
        p = _make_payload(directory=d, entry_point="run")
        with patch("importlib.util.spec_from_file_location") as mock_sfl:
            fake_mod = MagicMock()
            fake_mod.run = MagicMock(side_effect=TypeError("bad call"))
            fake_spec = MagicMock()
            mock_sfl.return_value = fake_spec
            with patch("importlib.util.module_from_spec", return_value=fake_mod):
                assert NativePayloadLoader._exec_python(p, "10.0.0.1", {}) is False

    def test_runtime_error_propagates(self, tmp_path):
        """RuntimeError is NOT caught (narrow except clause)."""
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.py"
        src.write_text("def run(target, options): return True\n")
        p = _make_payload(directory=d, entry_point="run")
        with patch("importlib.util.spec_from_file_location") as mock_sfl:
            fake_mod = MagicMock()
            fake_mod.run = MagicMock(side_effect=RuntimeError("boom"))
            fake_spec = MagicMock()
            mock_sfl.return_value = fake_spec
            with patch("importlib.util.module_from_spec", return_value=fake_mod):
                with pytest.raises(RuntimeError, match="boom"):
                    NativePayloadLoader._exec_python(p, "10.0.0.1", {})


# === _exec_c ===

class TestExecC:
    def test_no_source(self):
        p = _make_payload()
        with patch.object(type(p), "source_path", new_callable=PropertyMock, return_value=None):
            assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    def test_source_not_exists(self, tmp_path):
        p = _make_payload()
        fake_path = tmp_path / "nonexistent.c"
        with patch.object(type(p), "source_path", new_callable=PropertyMock, return_value=fake_path):
            assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    @patch.object(NativePayloadLoader, "_find_compiler", return_value=None)
    def test_no_compiler(self, _, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        src = d / "payload.c"
        src.write_text("int run(char* t, int p) { return 0; }\n")
        p = _make_payload(directory=d, language="c")
        assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_compiler", return_value="gcc")
    def test_compilation_fails(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").write_text("bad\n")
        p = _make_payload(directory=d, language="c")
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    @patch("ctypes.CDLL")
    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_compiler", return_value="gcc")
    def test_symbol_not_found(self, _, mock_run, mock_cdll, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").write_text("int other() { return 0; }\n")
        p = _make_payload(directory=d, language="c", entry_point="run")
        mock_run.return_value = MagicMock(returncode=0)
        lib = MagicMock(spec=[])
        mock_cdll.return_value = lib
        assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    @patch("ctypes.CDLL")
    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_compiler", return_value="gcc")
    def test_successful_execution(self, _, mock_run, mock_cdll, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").write_text("int run(char* t, int p) { return 42; }\n")
        p = _make_payload(directory=d, language="c", entry_point="run")
        mock_run.return_value = MagicMock(returncode=0)
        lib = MagicMock()
        lib.run = MagicMock(return_value=42)
        mock_cdll.return_value = lib
        assert NativePayloadLoader._exec_c(p, "10.0.0.1", {"port": 502}) is True

    @patch("ctypes.CDLL")
    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_compiler", return_value="gcc")
    def test_ctypes_exception(self, _, mock_run, mock_cdll, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").write_text("int run() { return 0; }\n")
        p = _make_payload(directory=d, language="c")
        mock_run.return_value = MagicMock(returncode=0)
        mock_cdll.side_effect = OSError("Cannot load")
        assert NativePayloadLoader._exec_c(p, "1.2.3.4", {}) is False

    @patch("ctypes.CDLL")
    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_compiler", return_value="gcc")
    def test_cleanup_runs_in_finally(self, _, mock_run, mock_cdll, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.c").write_text("int run(char* t, int p) { return 0; }\n")
        p = _make_payload(directory=d, language="c", entry_point="run")
        mock_run.return_value = MagicMock(returncode=0)
        lib = MagicMock()
        lib.run = MagicMock(return_value=0)
        mock_cdll.return_value = lib
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            NativePayloadLoader._exec_c(p, "1.2.3.4", {})
            tmpdir = tmp_path / ".tmp"
            if tmpdir.exists():
                assert list(tmpdir.glob("*.so")) == []
                assert list(tmpdir.glob("*.bin")) == []


# === _exec_rust ===

class TestExecRust:
    def test_no_source(self):
        p = _make_payload(language="rust")
        with patch.object(type(p), "source_path", new_callable=PropertyMock, return_value=None):
            assert NativePayloadLoader._exec_rust(p, "1.2.3.4", {}) is False

    @patch.object(NativePayloadLoader, "_find_rustc", return_value=None)
    def test_no_rustc(self, _, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        assert NativePayloadLoader._exec_rust(p, "1.2.3.4", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_rustc", return_value="rustc")
    def test_compilation_fails(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        mock_run.return_value = MagicMock(returncode=1, stderr="error[E0001]")
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_rust(p, "1.2.3.4", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_rustc", return_value="rustc")
    def test_successful_execution(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        mock_run.side_effect = [MagicMock(returncode=0), MagicMock(returncode=0)]
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_rust(p, "10.0.0.1", {}) is True

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_rustc", return_value="rustc")
    def test_execution_nonzero_return(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        mock_run.side_effect = [MagicMock(returncode=0), MagicMock(returncode=1)]
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_rust(p, "10.0.0.1", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_rustc", return_value="rustc")
    def test_exception_during_exec(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.rs").touch()
        p = _make_payload(directory=d, language="rust")
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="rustc", timeout=60)
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_rust(p, "10.0.0.1", {}) is False


# === _exec_go ===

class TestExecGo:
    def test_no_source(self):
        p = _make_payload(language="go")
        with patch.object(type(p), "source_path", new_callable=PropertyMock, return_value=None):
            assert NativePayloadLoader._exec_go(p, "1.2.3.4", {}) is False

    @patch.object(NativePayloadLoader, "_find_go", return_value=None)
    def test_no_go(self, _, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        assert NativePayloadLoader._exec_go(p, "1.2.3.4", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_go", return_value="go")
    def test_compilation_fails(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        mock_run.return_value = MagicMock(returncode=1, stderr="build error")
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_go(p, "1.2.3.4", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_go", return_value="go")
    def test_successful_execution(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        mock_run.side_effect = [MagicMock(returncode=0), MagicMock(returncode=0)]
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_go(p, "10.0.0.1", {}) is True

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_go", return_value="go")
    def test_execution_nonzero_return(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        mock_run.side_effect = [MagicMock(returncode=0), MagicMock(returncode=1)]
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_go(p, "10.0.0.1", {}) is False

    @patch("subprocess.run")
    @patch.object(NativePayloadLoader, "_find_go", return_value="go")
    def test_exception_during_exec(self, _, mock_run, tmp_path):
        d = tmp_path / "pl"
        d.mkdir()
        (d / "payload.go").touch()
        p = _make_payload(directory=d, language="go")
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="go", timeout=60)
        with patch("industrialxpl.core.native.loader._PROJECT_TMP", tmp_path / ".tmp"):
            assert NativePayloadLoader._exec_go(p, "10.0.0.1", {}) is False


# === Compiler discovery helpers ===

class TestFindCompiler:
    @patch("subprocess.run")
    @patch("sys.platform", "linux")
    def test_finds_gcc(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert NativePayloadLoader._find_compiler() == "gcc"

    @patch("subprocess.run")
    @patch("sys.platform", "linux")
    def test_finds_clang_when_gcc_missing(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd == ["which", "gcc"]:
                return MagicMock(returncode=1)
            if cmd == ["which", "cc"]:
                return MagicMock(returncode=1)
            if cmd == ["which", "clang"]:
                return MagicMock(returncode=0)
            return MagicMock(returncode=1)
        mock_run.side_effect = side_effect
        assert NativePayloadLoader._find_compiler() == "clang"

    @patch("subprocess.run")
    @patch("sys.platform", "linux")
    def test_returns_none_when_no_compiler(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert NativePayloadLoader._find_compiler() is None

    @patch("subprocess.run")
    @patch("sys.platform", "win32")
    def test_uses_where_on_windows(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert NativePayloadLoader._find_compiler() == "gcc"
        first_call = mock_run.call_args_list[0]
        assert first_call[0][0] == ["where", "gcc"]


class TestFindRustc:
    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_rustc_via_exists(self, mock_exists, mock_run):
        mock_exists.return_value = True
        assert NativePayloadLoader._find_rustc() == "rustc"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_rustc_via_which(self, mock_exists, mock_run):
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=0)
        assert NativePayloadLoader._find_rustc() == "rustc"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_cargo_rustc(self, mock_exists, mock_run):
        cargo_path = os.path.expanduser("~/.cargo/bin/rustc")
        def exists_side_effect(path):
            return path == cargo_path
        mock_exists.side_effect = exists_side_effect
        mock_run.return_value = MagicMock(returncode=1)
        assert NativePayloadLoader._find_rustc() == cargo_path

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_returns_none_when_no_rustc(self, mock_exists, mock_run):
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1)
        assert NativePayloadLoader._find_rustc() is None


class TestFindGo:
    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_go_via_exists(self, mock_exists, mock_run):
        mock_exists.return_value = True
        assert NativePayloadLoader._find_go() == "go"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_go_via_which(self, mock_exists, mock_run):
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=0)
        assert NativePayloadLoader._find_go() == "go"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_finds_usr_local_go(self, mock_exists, mock_run):
        def exists_side_effect(path):
            return path == "/usr/local/go/bin/go"
        mock_exists.side_effect = exists_side_effect
        mock_run.return_value = MagicMock(returncode=1)
        assert NativePayloadLoader._find_go() == "/usr/local/go/bin/go"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_returns_none_when_no_go(self, mock_exists, mock_run):
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1)
        assert NativePayloadLoader._find_go() is None


# === Module-level constants ===

class TestModuleConstants:
    def test_contrib_relative_is_path(self):
        assert isinstance(_CONTRIB_RELATIVE, Path)

    def test_package_contrib_is_path(self):
        assert isinstance(_PACKAGE_CONTRIB, Path)

    def test_project_tmp_is_path(self):
        assert isinstance(_PROJECT_TMP, Path)

    def test_contrib_relative_ends_with_native_payloads(self):
        assert _CONTRIB_RELATIVE.parts[-2:] == ("contrib", "native-payloads")

    @patch.dict(os.environ, {"IXF_NATIVE_PATH": "/custom/path"})
    def test_env_override(self):
        result = Path(os.environ.get("IXF_NATIVE_PATH", str(_CONTRIB_RELATIVE)))
        assert result == Path("/custom/path")
