"""Configuration for bottle-filling virtual plant.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AppConfig:
    """Runtime config for plant services."""

    bind_host: str = "127.0.0.1"
    expose_lan: bool = False
    lab_profile: str = "vulnerable"
    opcua_profile: str = "insecure"
    world_port: int = 80
    hmi_port: int = 8080
    control_port: int = 8082
    modbus_port: int = 15020
    opcua_port: int = 14840
    tick_seconds: float = 0.02
    log_level: str = "INFO"
    world_fallback_port: int = 18080
    hmi_fallback_port: int = 18081
    control_fallback_port: int = 18082
