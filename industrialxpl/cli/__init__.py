"""CLI package: interactive shell, tab completion and command dispatch.

Command mixins break the IXFInterpreter monolith into manageable groups:
  MITRECommandsMixin   : CVE, MITRE, TTP commands
  MalwareCommandsMixin : malware research, C2, botnet
  ICSCommandsMixin     : ICS-tools vendor, NSE, assess
  StatsCommandsMixin   : stats, vendors, protocols, coverage
  SASTCommandsMixin    : LLM key, SAST analysis
"""

from industrialxpl.cli.commands_ics import ICSCommandsMixin
from industrialxpl.cli.commands_malware import MalwareCommandsMixin
from industrialxpl.cli.commands_mitre import MITRECommandsMixin
from industrialxpl.cli.commands_sast import SASTCommandsMixin
from industrialxpl.cli.commands_stats import StatsCommandsMixin

__all__ = [
    "ICSCommandsMixin",
    "MalwareCommandsMixin",
    "MITRECommandsMixin",
    "SASTCommandsMixin",
    "StatsCommandsMixin",
]
