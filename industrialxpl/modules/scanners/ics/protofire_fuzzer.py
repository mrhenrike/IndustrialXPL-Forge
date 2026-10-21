"""Wrapper stub for Protofire modular OT/ICS protocol fuzzer.

Source: https://github.com/ridpath/protofire
License: verify
SRC-ID: SRC-993
Category: OT fuzzing, modular, plugin support

Protofire is a modular OT/ICS protocol fuzzer with plugin support
for custom protocol definitions. Enables targeted fuzzing of
proprietary industrial protocols.
"""

from dataclasses import dataclass


@dataclass
class ProtofireConfig:
    target: str = ""
    port: int = 502
    protocol_plugin: str | None = None
    seed_corpus: str | None = None
    max_iterations: int = 10000
