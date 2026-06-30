"""Docker stack manager for incorporated lab malware (Lisa botnet)."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

_PKG = Path(__file__).resolve().parents[2]
LISA_VENDOR = _PKG / "resources" / "vendor" / "submodules__malwares__lisa"
LISA_OVERLAY = _PKG / "lab_overlays" / "lisa"
LISA_OVERLAY_COMPOSE = LISA_OVERLAY / "docker-compose.override.yml"
LISA_REQ_OVERLAY = LISA_OVERLAY / "requirements.ixf.txt"


class DockerStackManager:
    def __init__(self, compose_dir: Path | None = None) -> None:
        self.compose_dir = compose_dir or LISA_VENDOR

    def compose_files(self) -> list[str]:
        files = [str(self.compose_dir / "docker-compose.yml")]
        if LISA_OVERLAY_COMPOSE.is_file():
            files.append(str(LISA_OVERLAY_COMPOSE))
        return files

    def _stage_overlay_files(self) -> None:
        """Copy IXF overlay artifacts into vendor build context."""
        if LISA_REQ_OVERLAY.is_file():
            import shutil
            shutil.copy2(LISA_REQ_OVERLAY, self.compose_dir / "requirements.ixf.txt")

    def _compose_base(self) -> list[str]:
        out: list[str] = []
        for f in self.compose_files():
            out.extend(["-f", f])
        return out

    def docker_available(self) -> bool:
        return bool(shutil.which("docker"))

    def compose_cmd(self) -> list[str]:
        if shutil.which("docker"):
            return ["sudo", "docker", "compose"] if not self._docker_accessible() else ["docker", "compose"]
        return []

    def _docker_accessible(self) -> bool:
        try:
            r = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def status(self) -> dict[str, Any]:
        if not self.docker_available():
            return {"success": False, "error": "docker not installed"}
        if not (self.compose_dir / "docker-compose.yml").is_file():
            return {"success": False, "error": "docker-compose.yml missing"}
        try:
            r = subprocess.run(
                self.compose_cmd() + self._compose_base() + ["ps"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.compose_dir),
            )
            return {
                "success": r.returncode == 0,
                "stdout": (r.stdout or "")[:2000],
                "stderr": (r.stderr or "")[:500],
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def up(self, build: bool = True, detach: bool = True) -> dict[str, Any]:
        if not self.docker_available():
            return {"success": False, "error": "docker not installed — apt install docker.io docker-compose-plugin"}
        self._stage_overlay_files()
        cmd = self.compose_cmd() + self._compose_base() + ["up"]
        if detach:
            cmd.append("-d")
        if build:
            cmd.append("--build")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900, cwd=str(self.compose_dir))
            return {
                "success": r.returncode == 0,
                "stdout": (r.stdout or "")[:1500],
                "stderr": (r.stderr or "")[:800],
                "url": "http://127.0.0.1:4242",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "docker compose timeout"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def down(self) -> dict[str, Any]:
        if not self.docker_available():
            return {"success": False, "error": "docker not installed"}
        try:
            r = subprocess.run(
                self.compose_cmd()
                + self._compose_base()
                + ["down"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.compose_dir),
            )
            return {"success": r.returncode == 0, "stdout": (r.stdout or "")[:500]}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def wait_http(self, url: str = "http://127.0.0.1:4242", timeout: int = 120) -> dict[str, Any]:
        import urllib.error
        import urllib.request
        deadline = time.time() + timeout
        last_err = ""
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    if resp.status < 500:
                        return {"success": True, "url": url, "status": resp.status}
            except (urllib.error.URLError, OSError) as exc:
                last_err = str(exc)
            time.sleep(2)
        return {"success": False, "error": last_err or "timeout"}
