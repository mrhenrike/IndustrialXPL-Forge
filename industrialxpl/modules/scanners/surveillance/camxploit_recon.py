"""Wrapper stub for CamXploit IP camera reconnaissance.

Source: https://github.com/spyboy-productions/CamXploit
License: verify
SRC-ID: SRC-997
Category: Surveillance, IP cameras, RTSP, default credentials, non-standard ports

CamXploit performs reconnaissance against IP cameras: discovers
devices, tests default credentials, and identifies non-standard
RTSP/HTTP ports.
"""

from dataclasses import dataclass


@dataclass
class CamXploitConfig:
    target: str = ""
    scan_rtsp: bool = True
    scan_http: bool = True
    test_defaults: bool = True
    timeout: int = 5
