"""Shared wordlist loader for credential modules.

Loads credentials from text files (user:pass per line) or CSV files,
falling back to an empty list when the file is missing. All credential
data lives in resources/wordlists/ as flat files.
"""

from __future__ import annotations

import csv
from pathlib import Path

WORDLISTS_DIR = Path(__file__).resolve().parents[2] / "resources" / "wordlists"


def load_credential_pairs(filename: str) -> list[tuple[str, str]]:
    """Load user:password pairs from a .txt wordlist file.

    Lines starting with '#' are ignored. Format: ``username:password``
    (empty username or password is valid).
    """
    path = WORDLISTS_DIR / filename
    if not path.is_file():
        return []
    pairs: list[tuple[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pwd = line.split(":", 1)
                pairs.append((user, pwd))
            else:
                pairs.append((line, ""))
    return pairs


def load_single_column(filename: str) -> list[str]:
    """Load a single-value-per-line wordlist (e.g. SNMP communities, usernames)."""
    path = WORDLISTS_DIR / filename
    if not path.is_file():
        return []
    values: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            values.append(line)
    return values


def load_csv_rows(filename: str) -> list[dict[str, str]]:
    """Load a CSV file as list of dicts (DictReader)."""
    path = WORDLISTS_DIR / filename
    if not path.is_file():
        return []
    rows: list[dict[str, str]] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows


def load_weighted_csv(filename: str) -> list[tuple[str, str, int]]:
    """Load CSV with username,password,weight columns."""
    rows = load_csv_rows(filename)
    result: list[tuple[str, str, int]] = []
    for row in rows:
        user = row.get("username", "")
        pwd = row.get("password", "")
        try:
            weight = int(row.get("weight", "1"))
        except ValueError:
            weight = 1
        result.append((user, pwd, weight))
    return result


def load_variant_csv(filename: str) -> list[tuple[str, str, str]]:
    """Load CSV with username,password,variant columns."""
    rows = load_csv_rows(filename)
    result: list[tuple[str, str, str]] = []
    for row in rows:
        result.append((
            row.get("username", ""),
            row.get("password", ""),
            row.get("variant", "") or row.get("device", ""),
        ))
    return result


def load_community_csv(filename: str) -> list[tuple[str, str]]:
    """Load CSV with community,context columns."""
    rows = load_csv_rows(filename)
    return [(r.get("community", ""), r.get("context", "")) for r in rows]
