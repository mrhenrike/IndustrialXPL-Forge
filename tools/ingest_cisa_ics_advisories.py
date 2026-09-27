#!/usr/bin/env python3
"""Ingest CISA ICS advisories for 2025+ CVE candidates (issue #2)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "industrialxpl" / "resources" / "cve" / "cisa_ics_2025_ingest.json"
ADVISORY_URL = "https://www.cisa.gov/ics-advisories"


def fetch_advisory_index() -> list[dict]:
    try:
        import requests
        r = requests.get(ADVISORY_URL, timeout=30)
        r.raise_for_status()
        text = r.text
    except Exception as exc:
        return [{"error": str(exc), "source": ADVISORY_URL}]
    cves = sorted(set(re.findall(r"CVE-2025-\d+", text)))
    return [{"cve_id": c, "source": "cisa_ics_advisories", "year": 2025} for c in cves]


def main() -> int:
    rows = fetch_advisory_index()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_from": ADVISORY_URL, "count": len(rows), "cves": rows}
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("Wrote {} ({} entries)".format(OUT, len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
