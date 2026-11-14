"""Archive detection and hash extraction dispatch."""

from __future__ import annotations

import zipfile
from pathlib import Path

from .models import ArchiveInfo, ExtractedHash, ExtractError
from .rar_extract import RAR3_MAGIC, RAR5_MAGIC, extract_rar_hash
from .zip_extract import extract_zip_hash

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


def _read_head(path: Path, size: int = 8) -> bytes:
    with path.open("rb") as fh:
        return fh.read(size)


def detect_archive(path: str | Path) -> ArchiveInfo:
    path = Path(path)
    if not path.exists():
        raise ExtractError("文件不存在。")
    if not path.is_file():
        raise ExtractError("请选择一个文件，而不是文件夹。")
    if path.stat().st_size == 0:
        raise ExtractError("文件为空。")

    suffix = path.suffix.lower()
    head = _read_head(path)
    size_text = _format_size(path.stat().st_size)

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return ArchiveInfo(
            path=path,
            kind="zip",
            label="ZIP",
            detail=f"{size_text} · 标准 ZIP 容器",
        )

    if head.startswith(RAR5_MAGIC):
        return ArchiveInfo(
            path=path,
            kind="rar5",
            label="RAR5",
            detail=f"{size_text} · WinRAR 5.x 格式",
        )

    if head.startswith(RAR3_MAGIC):
        return ArchiveInfo(
            path=path,
            kind="rar3",
            label="RAR3",
            detail=f"{size_text} · WinRAR 3.x/4.x 格式",
        )

    if head.startswith(SEVEN_ZIP_MAGIC):
        return ArchiveInfo(
            path=path,
            kind="7z",
            label="7-Zip",
            detail=f"{size_text} · 需要 $7z$ 哈希文件",
        )

    # Self-extracting / files with a prepended stub.  Scan a bounded prefix.
    try:
        prefix = path.open("rb").read(2 * 1024 * 1024)
    except OSError:
        prefix = b""

    if b"Rar!\x1a\x07\x01\x00" in prefix:
        return ArchiveInfo(path=path, kind="rar5", label="RAR5 (SFX)", detail=size_text)
    if b"Rar!\x1a\x07\x00" in prefix:
        return ArchiveInfo(path=path, kind="rar3", label="RAR3 (SFX)", detail=size_text)
    if SEVEN_ZIP_MAGIC in prefix:
        return ArchiveInfo(path=path, kind="7z", label="7-Zip (SFX)", detail=size_text)

    try:
        if zipfile.is_zipfile(path):
            return ArchiveInfo(path=path, kind="zip", label="ZIP", detail=size_text)
    except OSError:
        pass

    if suffix in (".zip", ".rar", ".7z"):
        raise ExtractError(
            f"文件扩展名是 {suffix}，但内容不是可识别的 {suffix[1:].upper()} 格式。",
            "文件可能已损坏、被加密容器包裹，或扩展名不正确。",
        )

    raise ExtractError(
        "暂不支持这种压缩包格式。",
        "支持 ZIP（ZipCrypto/AES）和 RAR3/RAR5；其他格式可用“哈希文件”模式。",
    )


def extract_hash(info: ArchiveInfo) -> ExtractedHash:
    if info.kind in ("zip", "zip-aes"):
        return extract_zip_hash(info.path)
    if info.kind in ("rar3", "rar5"):
        return extract_rar_hash(info.path)
    if info.kind == "7z":
        raise ExtractError(
            "7z 自动提取需要 7z2hashcat，而 hashcat 8.0.0 官方压缩包未附带它。",
            "请先用 7z2hashcat 生成 $7z$ 哈希，然后点击“使用哈希文件”载入；"
            "或者用 7-Zip 将文件重新打包为 ZIP 后再破解。",
        )
    raise ExtractError("不支持的压缩包类型。")


def _format_size(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"
