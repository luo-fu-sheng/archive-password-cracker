"""Shared data models for the archive password cracker."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


MODE_NAMES: dict[int, str] = {
    11600: "7-Zip",
    12500: "RAR3-hp",
    13000: "RAR5",
    13600: "WinZip AES",
    17200: "PKZIP 压缩",
    17210: "PKZIP 存储",
    17220: "PKZIP 多文件",
    17225: "PKZIP 混合多文件",
    17230: "PKZIP 仅校验",
    23700: "RAR3 存储",
    23800: "RAR3 压缩",
}


class ExtractError(Exception):
    """Raised when an archive hash cannot be extracted."""

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


@dataclass
class ArchiveInfo:
    path: Path
    kind: str                     # zip / rar3 / rar5 / 7z / hash
    label: str                    # human readable, e.g. "ZIP · AES-256"
    encrypted: bool = True
    entry: str = ""
    detail: str = ""
    hash_file: Optional[Path] = None


@dataclass
class ExtractedHash:
    mode: int
    hash_line: str
    kind: str
    label: str
    entry: str = ""
    encrypted: bool = True
    partial: bool = False
    detail: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def mode_name(self) -> str:
        return MODE_NAMES.get(self.mode, f"模式 {self.mode}")


@dataclass
class CrackResult:
    found: bool
    password: str = ""
    exit_code: int = 0
    message: str = ""
    elapsed: float = 0.0
    tried: int = 0
    total: int = 0
