"""Minimal HTTP client mixin for IXF exploit modules.

Provides HTTPClient base class for modules that need HTTP requests.
Uses Python's urllib (stdlib) + optional requests library.
"""

import socket
import urllib.request
import urllib.error
import ssl
from typing import Optional


class HTTPClient:
    """Lightweight HTTP client mixin for IXF exploit modules."""

    def _http_request(
        self,
        method: str,
        host: str,
        port: int,
        path: str,
        headers: Optional[dict] = None,
        data: Optional[bytes] = None,
        timeout: int = 10,
        use_ssl: bool = False,
        verify_ssl: bool = False,
    ):
        """Make an HTTP request. Returns urllib response or None on error."""
        scheme = "https" if use_ssl else "http"
        url = "{}://{}:{}{}".format(scheme, host, port, path)

        ctx = None
        if use_ssl and not verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if not req.has_header("User-Agent"):
            req.add_header("User-Agent", "Mozilla/5.0")

        try:
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except (urllib.error.HTTPError, urllib.error.URLError, Exception):
            return None

    def http_get(self, host, port, path, **kwargs):
        return self._http_request("GET", host, port, path, **kwargs)

    def http_post(self, host, port, path, data=None, **kwargs):
        if isinstance(data, str):
            data = data.encode()
        return self._http_request("POST", host, port, path, data=data, **kwargs)
