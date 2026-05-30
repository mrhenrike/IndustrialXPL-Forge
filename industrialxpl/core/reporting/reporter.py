"""IXF session report generator."""

import datetime
import json
from pathlib import Path

PROJECT_TMP = Path(__file__).resolve().parents[3] / ".tmp"
PROJECT_TMP.mkdir(parents=True, exist_ok=True)


class IXFReporter:
    """Generate assessment reports for the current IXF session."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def add_finding(self, finding: dict) -> None:
        self.findings.append(finding)

    def generate(self, fmt: str = "json") -> str:
        ts = datetime.datetime.utcnow().isoformat()
        data = {
            "assessment_id": "ixf-{}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S")),
            "generated": ts,
            "findings": self.findings,
        }
        date_str = datetime.date.today().isoformat()
        out = PROJECT_TMP / "ixf_report_{}.{}".format(date_str, fmt)
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(out)
