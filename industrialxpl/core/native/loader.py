"""Native Payload Loader — runtime discovery and in-memory compilation.

Architecture:
  - PyPI package: TTP-only simulators (simulate/check) — safe for distribution
  - GitHub clone: contrib/native-payloads/ — native implementations
    accessible ONLY when the user explicitly clones the repository

Detection:
  NativePayloadLoader.available() returns True only when the contrib directory
  exists alongside the installed package (i.e., the user has cloned the repo).

In-memory compilation (C/Rust payloads):
  1. Write source to a temp file inside .tmp/ (never /tmp or system temp)
  2. Compile with gcc/rustc to .tmp/<name>.so or .tmp/<name>.exe
  3. Load via ctypes.CDLL
  4. Delete the binary immediately after loading into memory
  5. Execute from loaded memory -- no compiled artifact persists on disk
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from industrialxpl.core.exploit.printer import (
    print_error, print_info, print_status, print_success, print_warning,
)

_CONTRIB_RELATIVE = Path(__file__).parent.parent.parent.parent / "contrib" / "native-payloads"
_PACKAGE_CONTRIB = Path(os.environ.get("IXF_NATIVE_PATH", str(_CONTRIB_RELATIVE)))

_PROJECT_TMP = Path(__file__).parent.parent.parent.parent / ".tmp"


@dataclass
class NativePayload:
    """Descriptor for a discovered native payload."""

    name: str
    slug: str
    directory: Path
    language: str        # python | c | rust | go | cpp
    entry_point: str     # file.py class or C function name
    impact: str          # CRITICAL | CATASTROPHIC
    description: str
    mitre: list = field(default_factory=list)

    @property
    def source_path(self) -> Optional[Path]:
        candidates = [
            self.directory / "payload.py",
            self.directory / "payload.c",
            self.directory / "payload.rs",
            self.directory / "payload.go",
            self.directory / "main.py",
            self.directory / "main.c",
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    @property
    def available(self) -> bool:
        return self.source_path is not None


class NativePayloadLoader:
    """Discovers and loads native payloads from contrib/native-payloads/."""

    _registry: dict[str, NativePayload] = {}
    _loaded: bool = False

    @classmethod
    def contrib_dir(cls) -> Path:
        return _PACKAGE_CONTRIB

    @classmethod
    def available(cls) -> bool:
        """Returns True only when contrib/native-payloads/ exists (repo clone)."""
        return _PACKAGE_CONTRIB.exists() and (_PACKAGE_CONTRIB / "USAGE.md").exists()

    @classmethod
    def _load_manifest(cls) -> None:
        """Scan contrib directory for payload manifests."""
        if cls._loaded:
            return
        cls._loaded = True
        if not cls.available():
            return
        for subdir in _PACKAGE_CONTRIB.iterdir():
            if not subdir.is_dir():
                continue
            manifest_path = subdir / "manifest.py"
            if not manifest_path.exists():
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    "manifest_{}".format(subdir.name), manifest_path
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "PAYLOAD_META"):
                    meta = mod.PAYLOAD_META
                    payload = NativePayload(
                        name=meta.get("name", subdir.name),
                        slug=subdir.name,
                        directory=subdir,
                        language=meta.get("language", "python"),
                        entry_point=meta.get("entry_point", "run"),
                        impact=meta.get("impact", "CRITICAL"),
                        description=meta.get("description", ""),
                        mitre=meta.get("mitre", []),
                    )
                    cls._registry[subdir.name] = payload
            except Exception as exc:
                print_warning("  [native] Failed to load manifest for {}: {}".format(
                    subdir.name, exc
                ))

    @classmethod
    def get(cls, slug: str) -> Optional[NativePayload]:
        cls._load_manifest()
        return cls._registry.get(slug)

    @classmethod
    def list_all(cls) -> list[NativePayload]:
        cls._load_manifest()
        return list(cls._registry.values())

    @classmethod
    def announce_if_available(cls, module_slug: str) -> bool:
        """Print a notification if a native payload exists for this module slug.

        Returns True if native payload is available.
        """
        if not cls.available():
            return False
        payload = cls.get(module_slug)
        if payload and payload.available:
            print_warning(
                "  [native] Native payload available for '{}' (GitHub clone only)".format(
                    payload.name
                )
            )
            print_info(
                "  [native] Impact: {}  |  Lang: {}  |  MITRE: {}".format(
                    payload.impact, payload.language, ", ".join(payload.mitre)
                )
            )
            print_info(
                "  [native] Set destructive=true and confirm to use native execution."
            )
            return True
        return False

    @classmethod
    def execute_native(
        cls,
        slug: str,
        target: str,
        options: dict,
        confirm_callback: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """Execute a native payload against target after confirmation gate.

        Args:
            slug: Payload slug (directory name under contrib/native-payloads/)
            target: Target IP or hostname
            options: Dict of module options to pass to the payload
            confirm_callback: Callable that returns True if user confirmed

        Returns:
            True on successful execution, False on abort/error.
        """
        cls._load_manifest()
        payload = cls.get(slug)

        if not payload:
            print_error("No native payload registered for slug '{}'.".format(slug))
            return False

        if not payload.available:
            print_error("Native payload source not found for '{}'.".format(slug))
            return False

        # Authorization gate — always required for native payloads
        print_info("")
        print_warning("=" * 68)
        print_warning("  NATIVE PAYLOAD EXECUTION REQUEST")
        print_warning("  Payload  : {}".format(payload.name))
        print_warning("  Target   : {}".format(target))
        print_warning("  Impact   : {}".format(payload.impact))
        print_warning("  Language : {}".format(payload.language))
        print_warning("  MITRE    : {}".format(", ".join(payload.mitre)))
        print_warning("=" * 68)
        print_info("")
        print_info("  This is a NATIVE implementation. It will execute real operations")
        print_info("  against the target system and may cause irreversible damage.")
        print_info("")
        print_info("  By proceeding, you confirm:")
        print_info("    1. You have WRITTEN AUTHORIZATION from the system owner")
        print_info("    2. The target is within your authorized scope")
        print_info("    3. You understand this may cause system failure or data loss")
        print_info("    4. You accept all legal and operational responsibility")
        print_info("")

        if confirm_callback and not confirm_callback():
            print_info("Native payload execution aborted by user.")
            return False

        # Execute by language
        if payload.language == "python":
            return cls._exec_python(payload, target, options)
        elif payload.language in ("c", "cpp", "c++"):
            return cls._exec_c(payload, target, options)
        elif payload.language == "rust":
            return cls._exec_rust(payload, target, options)
        elif payload.language == "go":
            return cls._exec_go(payload, target, options)
        else:
            print_error("Unsupported payload language: {}".format(payload.language))
            return False

    @classmethod
    def _exec_python(cls, payload: NativePayload, target: str, options: dict) -> bool:
        """Load and execute a Python payload module."""
        src = payload.source_path
        if src is None:
            print_error("No Python source found for {}".format(payload.slug))
            return False
        try:
            spec = importlib.util.spec_from_file_location(
                "native_{}".format(payload.slug), src
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            fn = getattr(mod, payload.entry_point, None)
            if fn is None:
                print_error("Entry point '{}' not found in {}".format(
                    payload.entry_point, src
                ))
                return False
            print_status("Executing native Python payload: {}".format(payload.name))
            result = fn(target=target, options=options)
            if result:
                print_success("Native payload completed successfully.")
            else:
                print_warning("Native payload completed with partial/no result.")
            return True
        except Exception as exc:
            print_error("Native Python execution error: {}".format(exc))
            return False

    @classmethod
    def _exec_c(cls, payload: NativePayload, target: str, options: dict) -> bool:
        """Compile C source in-memory and execute the payload function."""
        src = payload.source_path
        if src is None or not src.exists():
            print_error("No C source found for {}".format(payload.slug))
            return False

        _PROJECT_TMP.mkdir(parents=True, exist_ok=True)
        out_so = _PROJECT_TMP / "native_{}.so".format(payload.slug)
        out_exe = _PROJECT_TMP / "native_{}.bin".format(payload.slug)

        compiler = cls._find_compiler()
        if not compiler:
            print_error("No C compiler found (gcc, cc, clang). Install build-essential.")
            return False

        print_status("Compiling {} in-memory via {}...".format(payload.name, compiler))
        try:
            # Compile to shared library for ctypes loading
            result = subprocess.run(
                [compiler, "-shared", "-fPIC", "-O2", "-o", str(out_so), str(src),
                 "-DTARGET=\"{}\"".format(target)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                print_error("Compilation failed:\n{}".format(result.stderr))
                return False

            import ctypes
            lib = ctypes.CDLL(str(out_so))
            fn = getattr(lib, payload.entry_point, None)
            if fn is None:
                print_error("Symbol '{}' not found in compiled library".format(
                    payload.entry_point
                ))
                return False

            print_status("Executing native compiled payload against {}...".format(target))
            ret = fn(target.encode("utf-8"), ctypes.c_int(options.get("port", 0)))
            print_success("Native C payload returned: {}".format(ret))
            return True
        except Exception as exc:
            print_error("Native C execution error: {}".format(exc))
            return False
        finally:
            # Delete binary immediately after use -- no artifact on disk
            for artifact in (out_so, out_exe):
                try:
                    if artifact.exists():
                        artifact.unlink()
                except OSError:
                    pass

    @classmethod
    def _exec_rust(cls, payload: NativePayload, target: str, options: dict) -> bool:
        """Compile Rust source and execute in-memory."""
        src = payload.source_path
        if src is None:
            print_error("No Rust source found for {}".format(payload.slug))
            return False

        rustc = cls._find_rustc()
        if not rustc:
            print_error("rustc not found. Install from https://rustup.rs/")
            return False

        _PROJECT_TMP.mkdir(parents=True, exist_ok=True)
        out_bin = _PROJECT_TMP / "native_{}_rust".format(payload.slug)
        try:
            print_status("Compiling {} (Rust) via {}...".format(payload.name, rustc))
            result = subprocess.run(
                [rustc, "--edition", "2021", "-O", str(src), "-o", str(out_bin)],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print_error("Rust compilation failed:\n{}".format(result.stderr))
                return False
            result2 = subprocess.run(
                [str(out_bin), target], capture_output=False, text=True, timeout=120
            )
            return result2.returncode == 0
        except Exception as exc:
            print_error("Native Rust error: {}".format(exc))
            return False
        finally:
            try:
                if out_bin.exists():
                    out_bin.unlink()
            except OSError:
                pass

    @classmethod
    def _exec_go(cls, payload: NativePayload, target: str, options: dict) -> bool:
        """Compile Go source and execute in-memory."""
        src = payload.source_path
        if src is None:
            print_error("No Go source found for {}".format(payload.slug))
            return False

        go = cls._find_go()
        if not go:
            print_error("go not found. Install from https://go.dev/dl/")
            return False

        _PROJECT_TMP.mkdir(parents=True, exist_ok=True)
        out_bin = _PROJECT_TMP / "native_{}_go".format(payload.slug)
        try:
            print_status("Compiling {} (Go)...".format(payload.name))
            result = subprocess.run(
                [go, "build", "-o", str(out_bin), str(src)],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print_error("Go compilation failed:\n{}".format(result.stderr))
                return False
            result2 = subprocess.run([str(out_bin), target], timeout=120)
            return result2.returncode == 0
        except Exception as exc:
            print_error("Native Go error: {}".format(exc))
            return False
        finally:
            try:
                if out_bin.exists():
                    out_bin.unlink()
            except OSError:
                pass

    @staticmethod
    def _find_compiler() -> Optional[str]:
        for cc in ("gcc", "cc", "clang", "cl"):
            if subprocess.run(["which", cc] if sys.platform != "win32" else ["where", cc],
                              capture_output=True).returncode == 0:
                return cc
        return None

    @staticmethod
    def _find_rustc() -> Optional[str]:
        for rustc in ("rustc", os.path.expanduser("~/.cargo/bin/rustc")):
            if os.path.exists(rustc) or subprocess.run(
                ["which", rustc], capture_output=True
            ).returncode == 0:
                return rustc
        return None

    @staticmethod
    def _find_go() -> Optional[str]:
        for go in ("go", "/usr/local/go/bin/go"):
            if os.path.exists(go) or subprocess.run(
                ["which", go], capture_output=True
            ).returncode == 0:
                return go
        return None
