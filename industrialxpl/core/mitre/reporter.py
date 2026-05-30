"""MITRE ATT&CK Navigator layer and report generator."""

import datetime
import json
from pathlib import Path
from typing import Optional

PROJECT_TMP = Path(__file__).resolve().parents[3] / ".tmp"
PROJECT_TMP.mkdir(parents=True, exist_ok=True)

STATUS_COLORS = {
    "VULNERABLE":          "#e63946",  # red
    "SIMULATED (VULNERABLE)": "#f4a261",  # orange
    "NOT_VULNERABLE":      "#2ecc71",  # green
    "POSSIBLY_VULNERABLE": "#f39c12",  # amber
    "NOT_IMPLEMENTED":     "#95a5a6",  # grey
    "DEFAULT":             "#457b9d",  # blue
}


class MitreSweepReporter:
    """Generate ATT&CK Navigator layers and HTML/JSON reports."""

    def __init__(self, results: Optional[list] = None) -> None:
        self.results = results or []

    def generate_layer(self, fmt: str = "layer") -> str:
        """Generate an ATT&CK Navigator JSON layer file."""
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, build_index
        build_index()

        techniques = []
        for tid, mods in TECHNIQUE_INDEX.items():
            color = STATUS_COLORS["DEFAULT"] if mods else "#cccccc"
            comment = "ixf: {}".format(mods[0]) if mods else "no module"
            techniques.append({
                "techniqueID": tid,
                "color": color,
                "comment": comment,
                "enabled": True,
                "score": len(mods),
            })

        layer = {
            "name": "IndustrialXPL-Forge Coverage",
            "versions": {"attack": "19", "navigator": "4.9", "layer": "4.5"},
            "domain": "ics-attack",
            "description": "IXF module coverage of MITRE ATT&CK for ICS v19.",
            "techniques": techniques,
            "gradient": {"colors": ["#cccccc", "#2ecc71"], "minValue": 0, "maxValue": 5},
            "legendItems": [
                {"label": "No module", "color": "#cccccc"},
                {"label": "1+ module", "color": "#457b9d"},
            ],
        }

        ts = datetime.date.today().isoformat()
        out = PROJECT_TMP / "ixf_mitre_layer_{}.json".format(ts)
        out.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        return str(out)

    def save(self, path: str) -> str:
        """Save sweep results to a JSON file."""
        data = {
            "assessment_id": "ixf-{}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S")),
            "generated": datetime.datetime.utcnow().isoformat(),
            "results": self.results,
        }
        out = Path(path)
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(out)

    def generate(self, fmt: str = "json") -> str:
        """Generate full session report."""
        ts = datetime.date.today().isoformat()
        out = PROJECT_TMP / "ixf_report_{}.{}".format(ts, fmt)
        data = {
            "assessment_id": "ixf-{}".format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S")),
            "generated": datetime.datetime.utcnow().isoformat(),
            "results": self.results,
        }
        if fmt == "json":
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            out.write_text(str(data), encoding="utf-8")
        return str(out)
