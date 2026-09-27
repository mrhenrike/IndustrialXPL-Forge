"""IXF REST API server — programmatic access (issue #9).

Usage:
  ixf serve --host 127.0.0.1 --port 8443

Uses stdlib HTTP by default; install `industrialxpl-forge[api]` for OpenAPI via FastAPI.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


def _json_response(handler: BaseHTTPRequestHandler, code: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def build_handler(token: str = "") -> type[BaseHTTPRequestHandler]:
    class IxfApiHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            return

        def _auth_ok(self) -> bool:
            if not token:
                return True
            hdr = self.headers.get("Authorization", "")
            return hdr == "Bearer {}".format(token)

        def do_GET(self) -> None:
            if not self._auth_ok():
                _json_response(self, 401, {"error": "unauthorized"})
                return
            path = urlparse(self.path).path
            if path == "/modules":
                from industrialxpl.core.exploit.utils import index_modules
                mods = index_modules()
                _json_response(self, 200, {"count": len(mods), "modules": mods[:200]})
                return
            if path == "/mitre/coverage":
                from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, build_index
                from industrialxpl.core.mitre.tactics import TACTIC_TIDS
                build_index()
                total = sum(len(v) for v in TACTIC_TIDS.values())
                covered = len(TECHNIQUE_INDEX)
                _json_response(self, 200, {
                    "techniques_indexed": covered,
                    "technique_slots": total,
                    "coverage_pct": int(covered / total * 100) if total else 0,
                })
                return
            if path in ("/", "/health"):
                _json_response(self, 200, {"status": "ok", "service": "IndustrialXPL-Forge API"})
                return
            _json_response(self, 404, {"error": "not found", "path": path})

        def do_POST(self) -> None:
            if not self._auth_ok():
                _json_response(self, 401, {"error": "unauthorized"})
                return
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                data = {}
            if path == "/scan":
                module = data.get("module", "scanners/ics/modbus_scanner")
                target = data.get("target", "127.0.0.1")
                _json_response(self, 200, {
                    "simulate": True,
                    "module": module,
                    "target": target,
                    "note": "Use ixf -e for live module execution; API queues scan jobs in lab mode",
                })
                return
            if path == "/sast":
                _json_response(self, 200, {
                    "simulate": True,
                    "module": "assessment/sast/firmware_binary_analyzer",
                    "note": "POST firmware path via ixf module for full SAST pipeline",
                })
                return
            _json_response(self, 404, {"error": "not found"})

    return IxfApiHandler


def run_server(host: str = "127.0.0.1", port: int = 8443, token: str = "") -> None:
    handler = build_handler(token)
    httpd = ThreadingHTTPServer((host, port), handler)
    print("IXF API listening on http://{}:{}".format(host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAPI server stopped.")
        httpd.shutdown()


def try_fastapi_app():
    """Optional FastAPI app when [api] extra installed."""
    try:
        from fastapi import FastAPI
    except ImportError:
        return None
    app = FastAPI(title="IndustrialXPL-Forge API", version="1.1.1")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/modules")
    def modules():
        from industrialxpl.core.exploit.utils import index_modules
        mods = index_modules()
        return {"count": len(mods)}

    return app
