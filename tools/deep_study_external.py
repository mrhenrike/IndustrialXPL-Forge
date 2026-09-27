#!/usr/bin/env python3
"""Deep-study external links from awesome-ics-malware manifest (fetch + text extract).

Usage:
  PYTHONPATH=. python3 tools/deep_study_external.py
  PYTHONPATH=. python3 tools/deep_study_external.py --limit 10
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "industrialxpl" / "resources" / "research" / "awesome-ics-malware"
MANIFEST = RESEARCH / "manifest.json"
STUDIES = RESEARCH / "studies"
SUMMARY = RESEARCH / "study_summary.json"

PROTOCOL_KW = re.compile(
    r"\b(modbus|iec[\s-]?104|iec[\s-]?61850|s7comm|dnp3|opc[\s-]?ua|bacnet|"
    r"profinet|mssql|triconex|tristation|mbus|m-bus)\b",
    re.I,
)
IXF_TARGET_HINTS = {
    "iec104": "core/ics/iec104_stack.py",
    "modbus": "modules/cve/malware/frostygoop_extended.go",
    "triton": "modules/cve/malware/triton_tristation_native.py",
    "pipedream": "modules/cve/malware/incontroller_pipedream_suite.py",
    "cosmicenergy": "modules/cve/malware/cosmicenergy_iec104.py",
    "industroyer": "modules/cve/malware/crashoverride_industroyer.py",
    "yara": "core/ics_tools/forensics_engine.py",
}


def _url_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _classify_content_type(url: str, data: bytes, content_type: str) -> str:
    ct = (content_type or "").lower()
    if "pdf" in ct or url.lower().endswith(".pdf"):
        return "pdf"
    if "html" in ct or "text" in ct:
        return "html"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:15].lower().startswith(b"<!doctype") or b"<html" in data[:500].lower():
        return "html"
    return "binary"


def _fetch(url: str, timeout: float = 25.0) -> tuple[str, bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "IXF-deep-study/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            return "ok", resp.read(2_000_000), ct
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404, 410):
            arch = "https://web.archive.org/web/0/{}".format(url)
            try:
                req2 = urllib.request.Request(arch, headers={"User-Agent": "IXF-deep-study/1.0"})
                with urllib.request.urlopen(req2, timeout=timeout) as resp:
                    ct = resp.headers.get("Content-Type", "")
                    return "ok_archive", resp.read(2_000_000), ct
            except (urllib.error.URLError, OSError, urllib.error.HTTPError):
                pass
        return "http_{}".format(exc.code), b"", ""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return "error:{}".format(type(exc).__name__), b"", ""


def _pdf_to_text(data: bytes) -> str:
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        return ""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        try:
            r = subprocess.run(
                [pdftotext, "-layout", tmp.name, "-"],
                capture_output=True,
                timeout=60,
            )
            if r.returncode == 0:
                return (r.stdout or b"").decode("utf-8", errors="replace")
        except (subprocess.TimeoutExpired, OSError):
            pass
    return ""


def _html_to_text(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text[:50000]


def _score_text(text: str, url: str) -> dict:
    protocols = sorted(set(m.group(0).lower() for m in PROTOCOL_KW.finditer(text)))
    score = 0
    if protocols:
        score += 1
    if len(text) > 2000:
        score += 1
    if any(k in url.lower() for k in ("dragos", "mandiant", "welivesecurity", "nozomi")):
        score += 1
    targets = []
    blob = (text + " " + url).lower()
    for kw, path in IXF_TARGET_HINTS.items():
        if kw in blob:
            targets.append(path)
    return {
        "incorporation_score": min(score, 3),
        "protocols": protocols[:12],
        "ixf_target_paths": sorted(set(targets))[:8],
        "text_chars": len(text),
    }


def study_url(entry: dict) -> dict:
    url = entry["url"]
    status, data, ct = _fetch(url)
    result: dict = {
        "url": url,
        "label": entry.get("label", ""),
        "fetch_status": status,
        "studied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if not status.startswith("ok") or not data:
        result["content_type"] = "none"
        result["incorporation_score"] = 0
        return result

    kind = _classify_content_type(url, data, ct)
    result["content_type"] = kind
    if kind == "pdf":
        text = _pdf_to_text(data)
        if not text.strip():
            result["note"] = "pdf binary only (install poppler-utils for text)"
            text = ""
    elif kind == "html":
        text = _html_to_text(data)
    else:
        text = ""
        result["note"] = "binary or unsupported"

    # store excerpt only — no full PDF in repo
    excerpt = text[:8000] if text else ""
    result["excerpt"] = excerpt
    result.update(_score_text(text, url))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Max URLs (0=all)")
    parser.add_argument("--retry-failed", action="store_true", help="Re-fetch only failed studies")
    parser.add_argument("--delay", type=float, default=0.3, help="Seconds between fetches")
    args = parser.parse_args()

    if not MANIFEST.is_file():
        print("run ingest_awesome_ics_malware.py first", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    urls = manifest.get("urls", [])
    if args.limit > 0:
        urls = urls[: args.limit]

    STUDIES.mkdir(parents=True, exist_ok=True)
    ok = 0
    scored: list[dict] = []
    for i, entry in enumerate(urls):
        uid = _url_id(entry["url"])
        out_path = STUDIES / "{}.json".format(uid)
        if out_path.is_file() and not args.retry_failed:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            scored.append(existing)
            if existing.get("fetch_status", "").startswith("ok"):
                ok += 1
            continue
        if out_path.is_file() and args.retry_failed:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            if existing.get("fetch_status", "").startswith("ok"):
                scored.append(existing)
                ok += 1
                continue
            out_path.unlink(missing_ok=True)
        print("[{}/{}] {}".format(i + 1, len(urls), entry["url"][:70]))
        result = study_url(entry)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        scored.append(result)
        if result.get("fetch_status", "").startswith("ok"):
            ok += 1
        time.sleep(args.delay)

    ratio = ok / len(urls) if urls else 0
    summary = {
        "studied": len(urls),
        "ok": ok,
        "ok_ratio": round(ratio, 3),
        "avg_score": round(
            sum(s.get("incorporation_score", 0) for s in scored) / max(len(scored), 1), 2
        ),
    }
    SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("study_summary: ok={}/{} ratio={:.2f} -> {}".format(ok, len(urls), ratio, SUMMARY))
    return 0


if __name__ == "__main__":
    sys.exit(main())
