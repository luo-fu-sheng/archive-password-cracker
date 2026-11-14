"""Recognise an existing hashcat hash file (used for 7z and other formats)."""

from __future__ import annotations

from pathlib import Path

from .models import MODE_NAMES, ExtractedHash, ExtractError


def inspect_hash_file(path: str | Path) -> ExtractedHash:
    path = Path(path)
    if not path.exists():
        raise ExtractError("哈希文件不存在。")
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ExtractError("哈希文件是空的。")

    line = lines[0]
    mode: int
    kind: str
    label: str

    if line.startswith("$7z$"):
        mode, kind, label = 11600, "7z-hash", "7-Zip"
    elif line.startswith("$pkzip2$") or line.startswith("$pkzip$"):
        mode, kind, label = 17200, "zip-hash", "PKZIP"
    elif line.startswith("$zip2$"):
        mode, kind, label = 13600, "zip-hash", "WinZip AES"
    elif line.startswith("$rar5$"):
        mode, kind, label = 13000, "rar-hash", "RAR5"
    elif line.startswith("$RAR3$*0*"):
        mode, kind, label = 12500, "rar-hash", "RAR3-hp"
    elif line.startswith("$RAR3$*1*"):
        mode, kind, label = 23800, "rar-hash", "RAR3"
    else:
        raise ExtractError(
            "无法识别这个哈希文件。",
            "支持 $pkzip2$ / $zip2$ / $rar5$ / $RAR3$ / $7z$ 开头的 hashcat 哈希。",
        )

    if len(lines) > 1:
        label += f" · {len(lines)} 条哈希"
    return ExtractedHash(
        mode=mode,
        hash_line=line,
        kind=kind,
        label=label,
        detail=f"已有哈希文件 · {MODE_NAMES.get(mode, mode)} · {len(lines)} 条记录",
    )
