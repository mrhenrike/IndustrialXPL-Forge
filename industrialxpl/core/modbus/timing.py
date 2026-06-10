"""Modbus scan timing profiles — T0 (paranoid) to T5 (insane).

Mirrors Nmap timing templates behaviour adapted for Modbus/TCP:

  T0  Paranoid   — 5 s timeout, 10 s between requests, 1 retry
  T1  Sneaky     — 3 s timeout,  5 s between requests, 1 retry
  T2  Polite     — 2 s timeout,  1 s between requests, 2 retries
  T3  Normal     — 1 s timeout, 300 ms between requests, 3 retries  (default)
  T4  Aggressive — 0.5 s timeout, 50 ms between requests, 2 retries
  T5  Insane     — 0.2 s timeout,   0 ms between requests, 1 retry
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import time


@dataclass(frozen=True)
class TimingProfile:
    level: int
    name: str
    socket_timeout: float     # seconds
    inter_request_delay: float  # seconds between consecutive requests
    retries: int
    max_rtt_timeout: float    # upper bound for response wait

    def sleep(self) -> None:
        """Block for the inter-request delay."""
        if self.inter_request_delay > 0:
            time.sleep(self.inter_request_delay)

    def __str__(self) -> str:
        return (
            "T{level} ({name}): timeout={timeout}s, "
            "delay={delay}ms, retries={retries}".format(
                level=self.level,
                name=self.name,
                timeout=self.socket_timeout,
                delay=int(self.inter_request_delay * 1000),
                retries=self.retries,
            )
        )


TIMING_PROFILES: Dict[int, TimingProfile] = {
    0: TimingProfile(0, "Paranoid",   socket_timeout=5.0,  inter_request_delay=10.0, retries=1, max_rtt_timeout=10.0),
    1: TimingProfile(1, "Sneaky",     socket_timeout=3.0,  inter_request_delay=5.0,  retries=1, max_rtt_timeout=5.0),
    2: TimingProfile(2, "Polite",     socket_timeout=2.0,  inter_request_delay=1.0,  retries=2, max_rtt_timeout=2.0),
    3: TimingProfile(3, "Normal",     socket_timeout=1.0,  inter_request_delay=0.3,  retries=3, max_rtt_timeout=1.0),
    4: TimingProfile(4, "Aggressive", socket_timeout=0.5,  inter_request_delay=0.05, retries=2, max_rtt_timeout=0.5),
    5: TimingProfile(5, "Insane",     socket_timeout=0.2,  inter_request_delay=0.0,  retries=1, max_rtt_timeout=0.2),
}

DEFAULT_TIMING = TIMING_PROFILES[3]


class ModbusTiming:
    """Helper to resolve a T-level string/int into a TimingProfile."""

    @staticmethod
    def resolve(value) -> TimingProfile:
        """Accept T3, 3, 't3', 'normal', etc."""
        if isinstance(value, int):
            level = value
        else:
            s = str(value).strip().lower().lstrip("t")
            # Accept name aliases
            _name_map = {
                "paranoid": 0, "sneaky": 1, "polite": 2,
                "normal": 3, "aggressive": 4, "insane": 5,
            }
            if s in _name_map:
                level = _name_map[s]
            else:
                try:
                    level = int(s)
                except ValueError:
                    raise ValueError(
                        "Invalid timing level '{}'. Use T0-T5 or names: "
                        "paranoid, sneaky, polite, normal, aggressive, insane.".format(value)
                    )
        if level not in TIMING_PROFILES:
            raise ValueError("Timing level must be 0-5, got: {}".format(level))
        return TIMING_PROFILES[level]

    @staticmethod
    def describe_all() -> str:
        lines = ["Modbus Timing Profiles (set timing T<n>):"]
        for lvl, p in TIMING_PROFILES.items():
            lines.append(
                "  T{:d}  {:10s}  timeout={:.1f}s  delay={:>5}ms  retries={}{}".format(
                    lvl,
                    p.name,
                    p.socket_timeout,
                    int(p.inter_request_delay * 1000),
                    p.retries,
                    "  [default]" if lvl == 3 else "",
                )
            )
        return "\n".join(lines)
