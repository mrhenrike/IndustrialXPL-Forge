"""Wrapper stub for Cameradar RTSP/CCTV camera hacking tool.

Source: https://github.com/Ullaakut/cameradar (5260 stars)
License: MIT
SRC-ID: SRC-163
Category: Surveillance, RTSP, CCTV, camera discovery, credential testing

Cameradar discovers and accesses RTSP video streams. Scans for
exposed cameras, tests default credentials, and extracts stream
routes from RTSP/HTTP services.
"""

from dataclasses import dataclass


@dataclass
class CameradarConfig:
    targets: str = ""
    ports: str = "554,8554"
    routes_file: str | None = None
    credentials_file: str | None = None
    timeout: int = 2
    threads: int = 4
    scan_speed: int = 4  # nmap timing 1-5
