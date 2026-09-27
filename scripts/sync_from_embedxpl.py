#!/usr/bin/env python3
"""One-shot sync: port high-value EmbedXPL-Forge core/modules into IndustrialXPL-Forge."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

EXF_ROOT = Path(__file__).resolve().parents[1].parent / "EmbedXPL-Forge" / "embedxpl"
IXF_ROOT = Path(__file__).resolve().parents[1] / "industrialxpl"

COPY_MAP = [
    ("core/session.py", "core/session.py"),
    ("core/pool.py", "core/pool.py"),
    ("core/ics", "core/ics"),
    ("core/shells", "core/shells"),
    ("core/exploit/encoders.py", "core/exploit/encoders.py"),
    ("core/exploit/payloads.py", "core/exploit/payloads.py"),
    ("core/exploit/shell.py", "core/exploit/shell.py"),
    ("core/exploit/shell_stager.py", "core/exploit/shell_stager.py"),
    ("core/exploit/char_by_char.py", "core/exploit/char_by_char.py"),
    ("core/exploit/module_target_scope.py", "core/exploit/module_target_scope.py"),
    ("modules/payloads", "modules/payloads"),
    ("modules/encoders", "modules/encoders"),
]


def rewrite(content: str) -> str:
    content = content.replace("embedxpl", "industrialxpl")
    content = content.replace("EmbedXPL-Forge", "IndustrialXPL-Forge")
    content = content.replace("EmbedXPL", "IndustrialXPL")
    return content


def copy_tree(src: Path, dst: Path) -> int:
    count = 0
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8", errors="replace")
        dst.write_text(rewrite(text), encoding="utf-8")
        return 1
    if not src.is_dir():
        return 0
    for p in src.rglob("*"):
        if not p.is_file() or p.suffix != ".py":
            continue
        rel = p.relative_to(src)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rewrite(p.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
        count += 1
    return count


def main() -> None:
    if not EXF_ROOT.is_dir():
        print("EmbedXPL-Forge not found at", EXF_ROOT)
        return
    total = 0
    for src_rel, dst_rel in COPY_MAP:
        src = EXF_ROOT / src_rel
        dst = IXF_ROOT / dst_rel
        n = copy_tree(src, dst)
        print("  {} -> {} ({} files)".format(src_rel, dst_rel, n))
        total += n
    print("Synced {} Python files from EmbedXPL.".format(total))


if __name__ == "__main__":
    main()
