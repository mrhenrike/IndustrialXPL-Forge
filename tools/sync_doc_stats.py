#!/usr/bin/env python3
"""Sync module/MITRE/NSE stats across README, docs and wiki markdown."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REPLACEMENTS = [
    ("1160%2B", "1190%2B"),
    ("1160+", "1190+"),
    ("976%2B", "1190%2B"),
    ("972%2B", "1190%2B"),
    ("976+", "1190+"),
    ("972+", "1190+"),
    ("74/90 técnicas (82%)", "96/103 técnicas (93%)"),
    ("74/90 techniques (82%)", "96/103 techniques (93%)"),
    ("74/90 técnicas", "96/103 técnicas"),
    ("74/90 techniques", "96/103 techniques"),
    ("74/90 (82%)", "96/103 (93%)"),
    ("74/90", "96/103"),
    ("82% cobertura", "93% cobertura"),
    ("82% coverage", "93% coverage"),
    ("( 82%)", "( 93%)"),
    ("79 técnicas mapeadas", "96+ técnicas mapeadas"),
    ("79 techniques mapped", "96+ techniques mapped"),
    ("All 79 techniques", "All 96+ techniques"),
    ("Todas as 79 técnicas", "Todas as 96+ técnicas"),
    ("976 modules indexed", "1193 modules indexed"),
    ("976 módulos indexados", "1193 módulos indexados"),
    ("976 modulos indexados", "1193 modulos indexados"),
    ("976 modules", "1193 modules"),
    ("976 módulos", "1193 módulos"),
    ("976 modulos", "1193 modulos"),
    ("Total: 976", "Total: 1193"),
    ("Total de módulos: 976", "Total de módulos: 1193"),
    ("Total de modulos: 976", "Total de modulos: 1193"),
    (" 976 módulos", " 1193 módulos"),
    (" 976 modules", " 1193 modules"),
    ("976/976", "1193/1193"),
    ("972/972", "1193/1193"),
    ("8 ICS Nmap scripts", "15 ICS Nmap scripts"),
    ("8 NSE scripts", "15 NSE scripts"),
    ("8 scripts NSE", "15 scripts NSE"),
    ("NSE: 8/8", "NSE: 15/15"),
    ("8/8 instalados", "15/15 instalados"),
    ("8/8 installed", "15/15 installed"),
    ("all 976 modules", "all 1193 modules"),
    ("todos os 976 módulos", "todos os 1193 módulos"),
    ("| `creds/` | ~55 |", "| `creds/` | ~71 |"),
    ("IXF v1.0.13", "IXF v1.1.1"),
    ("IXF v2.1.0", "IXF v1.1.1"),
    ("v1.0.15", "v1.1.1"),
    ("v1.0.14", "v1.1.1"),
    ("Total de módulos:     976", "Total de módulos:     1193"),
    ("Total modules: 976", "Total modules: 1193"),
    ("Total            976", "Total            1193"),
    ("| Total modules | 976 |", "| Total modules | 1193 |"),
    ("  Total Modules          976", "  Total Modules          1193"),
    ("  Total Modules: 976", "  Total Modules: 1193"),
    ("  Modules run:     976", "  Modules run:     1193"),
    ('"total_modules": 976', '"total_modules": 1193'),
    ("  Techniques Covered      74 / 90  (82%)", "  Techniques Covered      96 / 103  (93%)"),
    ("  MITRE techniques mapped: 74 / 90 (82%)", "  MITRE techniques mapped: 96 / 103 (93%)"),
    ("74 out of 90 techniques = **82%**", "96 out of 103 techniques = **93%**"),
    ("96/103 tecnicas (82%)", "96/103 tecnicas (93%)"),
    ("96/103 técnicas mapeadas (82%)", "96/103 técnicas mapeadas (93%)"),
    ("[i] Coverage: 82% (96/103 techniques)", "[i] Coverage: 93% (96/103 techniques)"),
    ("  TOTAL                                74       90      82%", "  TOTAL                                96      103      93%"),
    ("  TOTAL                                74        90       82%", "  TOTAL                                96        103       93%"),
    ("  TOTAL                                   74      90     82%", "  TOTAL                                   96     103     93%"),
    ("| **TOTAL** | | **101** | **74** | **82%** |", "| **TOTAL** | | **103** | **96** | **93%** |"),
    ("mapeando 1190+ módulos para 74 das 90 técnicas (cobertura de 82%)", "mapeando 1190+ módulos para 96 das 103 técnicas (cobertura de 93%)"),
    ("the 82% figure references that baseline", "the 93% figure reflects MITRE ATT&CK for ICS v19 matrix coverage"),
    ("a cifra de 82% referencia essa linha de base", "a cifra de 93% reflete a cobertura da matriz MITRE ATT&CK for ICS v19"),
    ("74 das 90 técnicas (cobertura de 82%)", "96 das 103 técnicas (cobertura de 93%)"),
]


def patch_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    orig = text
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    # badge Modules-976 -> 1190
    text = re.sub(r"Modules-976%2B", "Modules-1190%2B", text)
    text = re.sub(r"Módulos-976%2B", "Módulos-1190%2B", text)
    text = re.sub(r"Modulos-976%2B", "Modulos-1190%2B", text)
    if text != orig:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> int:
    targets: list[Path] = []
    for pattern in ("README*.md", "docs/**/*.md", "CHANGELOG.md"):
        targets.extend(ROOT.glob(pattern))
    if len(sys.argv) > 1:
        targets = [Path(p) for p in sys.argv[1:]]
    changed = 0
    for p in sorted(set(targets)):
        if "resources/vendor" in str(p):
            continue
        if patch_file(p):
            print("updated", p.relative_to(ROOT) if p.is_relative_to(ROOT) else p)
            changed += 1
    print(f"Done: {changed} files updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
