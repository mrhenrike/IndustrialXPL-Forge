#!/usr/bin/env python3
"""UDP helper that returns schema.txt after the CTF code. External oil VM only."""

from __future__ import annotations

import logging
import socket
from pathlib import Path


LOGGER = logging.getLogger("legacy.message")
PORT = 5021
CODE = b"bdkf84hj4cfbd5ce3ae91ef7021flv04\n"


def main() -> int:
    """Serve one UDP exchange and exit."""
    logging.basicConfig(level=logging.INFO)
    schema = Path(__file__).with_name("schema.txt")
    payload = schema.read_bytes() if schema.exists() else b"schema missing\n"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", PORT))
    try:
        info, addr = sock.recvfrom(1024)
        if info == CODE:
            sock.sendto(payload[:1024], addr)
        else:
            sock.sendto(b"\nWrong Code!!\nWe'll notify the Security Operation Center.\n", addr)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
