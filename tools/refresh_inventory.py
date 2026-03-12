from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
REPO_NAME = ROOT.name
OUTPUT_PATH = ROOT / f"inventory_{REPO_NAME}.md"
SUMMARY_PATH = ROOT / f"inventory_summary_{REPO_NAME}.json"
MAX_INLINE_BYTES = 200 * 1024
UTC_PLUS_ONE = timezone(timedelta(hours=1))
SKIP_NAMES = {"inventory.md"}
SKIP_PREFIXES = ("inventory_", "inventory_summary")
SKIP_PATHS = {PurePosixPath("tools/refresh_inventory.py")}
BINARY_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bin",
    ".bmp",
    ".class",
    ".db",
    ".dll",
    ".doc",
    ".docx",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".pyc",
    ".pyd",
    ".so",
    ".sqlite",
    ".svgz",
    ".tar",
    ".tif",
    ".tiff",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".whl",
    ".woff",
    ".woff2",
    ".zip",
}


def run_git_ls_files() -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rel_path = PurePosixPath(line)
        name = rel_path.name
        if rel_path in SKIP_PATHS:
            continue
        if name in SKIP_NAMES:
            continue
        if any(name.startswith(prefix) for prefix in SKIP_PREFIXES):
            continue
        paths.append(rel_path)
    return sorted(paths)


def detect_kind(rel_path: PurePosixPath, file_size: int, data: bytes) -> str:
    if rel_path.suffix.lower() in BINARY_EXTENSIONS:
        return "binary"
    if file_size > MAX_INLINE_BYTES:
        return "too_large"
    if b"\x00" in data:
        return "binary"
    return "text"


def decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("unknown", data, 0, 1, "unable to decode")


def render_section(rel_path: PurePosixPath) -> tuple[dict[str, object], str]:
    abs_path = ROOT / Path(rel_path)
    file_size = abs_path.stat().st_size
    data = abs_path.read_bytes()
    kind = detect_kind(rel_path, file_size, data)
    summary_entry: dict[str, object] = {
        "path": rel_path.as_posix(),
        "size": file_size,
        "kind": kind,
    }

    if kind == "binary":
        body = f"BINARY (omitted, {file_size} bytes)"
    elif kind == "too_large":
        body = f"OMITTED (too large, {file_size} bytes)"
    else:
        try:
            body = decode_text(data)
        except UnicodeDecodeError:
            summary_entry["kind"] = "unreadable"
            body = f"UNREADABLE ({file_size} bytes)"

    if not body.endswith("\n"):
        body += "\n"

    section = f"### {rel_path.as_posix()}\n````text\n{body}````\n"
    return summary_entry, section


def main() -> None:
    paths = run_git_ls_files()
    summary: list[dict[str, object]] = []
    sections: list[str] = []

    for rel_path in paths:
        entry, section = render_section(rel_path)
        summary.append(entry)
        sections.append(section)

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    timestamp = datetime.now(UTC_PLUS_ONE).strftime("%Y-%m-%d %H:%M:%S UTC+1")
    lines = [timestamp, "ROOT TREE", *[path.as_posix() for path in paths], ""]
    content = "\n".join(lines) + "\n" + "\n".join(sections)
    OUTPUT_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.name} with {len(paths)} entries")


if __name__ == "__main__":
    main()
