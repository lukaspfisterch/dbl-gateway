#!/usr/bin/env python3
"""Generate inventory_dbl-gateway.md from tracked files.

Respects .gitignore via `git ls-files`. Binary and large files are noted
but not inlined. Output is lexicographically sorted and diff-friendly.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_NAME = "inventory_dbl-gateway.md"
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2",
    ".pdf", ".exe", ".dll", ".so", ".dylib",
    ".sqlite", ".db",
}
MAX_INLINE_BYTES = 200_000  # 200 KB
EXCLUDE_PREFIXES = (
    "inventory_", "tools/refresh_inventory.py",
)


def tracked_files() -> list[str]:
    out = subprocess.check_output(
        ["git", "ls-files"], cwd=REPO_ROOT, text=True
    )
    paths = sorted(p.strip() for p in out.splitlines() if p.strip())
    return [p for p in paths if not any(p.startswith(e) for e in EXCLUDE_PREFIXES)]


def classify(path: str) -> tuple[str, str | None]:
    """Return (status, content_or_none)."""
    full = REPO_ROOT / path
    if not full.exists():
        return "MISSING", None
    ext = full.suffix.lower()
    if ext in BINARY_EXTS:
        return "BINARY (omitted)", None
    size = full.stat().st_size
    if size > MAX_INLINE_BYTES:
        return f"OMITTED (too large, {size:,} bytes)", None
    try:
        content = full.read_text(encoding="utf-8", errors="replace")
        return "ok", content
    except Exception:
        return "UNREADABLE", None


def main() -> None:
    os.chdir(REPO_ROOT)
    files = tracked_files()

    tz = timezone(timedelta(hours=1))
    ts = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S %Z")

    lines: list[str] = []
    lines.append(f"<!-- Generated: {ts} -->\n")
    lines.append("# Inventory: dbl-gateway\n\n")

    # Tree listing
    lines.append("## File Tree\n\n```\n")
    for f in files:
        lines.append(f"{f}\n")
    lines.append("```\n\n")

    # File contents
    lines.append("## File Contents\n\n")
    for f in files:
        status, content = classify(f)
        lines.append(f"### {f}\n\n")
        if status == "ok" and content is not None:
            ext = Path(f).suffix.lstrip(".")
            lines.append(f"```{ext}\n{content}")
            if not content.endswith("\n"):
                lines.append("\n")
            lines.append("```\n\n")
        else:
            lines.append(f"_{status}_\n\n")

    out_path = REPO_ROOT / INVENTORY_NAME
    out_path.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote {out_path} ({len(files)} files)")


if __name__ == "__main__":
    main()
