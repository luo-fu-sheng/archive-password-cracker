"""ZIP hash extraction for hashcat.

Supports traditional PKZIP encryption (ZipCrypto) and WinZip AES.
The produced lines follow the zip2john / hashcat formats:
    $pkzip2$...$/pkzip2$   -> modes 17200 / 17210 / 17220 ...
    $zip2$...$/zip2$       -> mode 13600
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from .models import ExtractedHash, ExtractError

LOCAL_SIG = 0x04034B50
_AES_EXTRA_ID = 0x9901

# Inline data is capped so a multi-GB archive cannot produce a multi-GB hash
# file.  For ZipCrypto the first 76 bytes are more than enough for the 12-byte
# header check plus a healthy ciphertext sample.  AES needs the whole stream
# for its HMAC, so it is never truncated.
_LEGACY_MAX_DATA = 300 * 1024       # hashcat PKZIP parser caps ciphertext at 320 KB
_AES_MAX_DATA = 8 * 1024 * 1024     # hashcat zip2 buffer is 0x200000 u32


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _parse_extra_fields(extra: bytes) -> list[tuple[int, bytes]]:
    fields: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 4 <= len(extra):
        field_id, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + size > len(extra):
            break
        fields.append((field_id, extra[pos : pos + size]))
        pos += size
    return fields


def _dos_time(zip_info: zipfile.ZipInfo) -> int:
    y, mo, d, h, mi, s = zip_info.date_time
    if y < 1980:
        y = 1980
    return ((h & 0x1F) << 11) | ((mi & 0x3F) << 5) | ((s // 2) & 0x1F)


def _read_at(fh, offset: int, size: int) -> bytes:
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise ExtractError("压缩包数据不完整，无法读取加密文件。")
    return data


def _local_header(fh, info: zipfile.ZipInfo, file_size: int) -> dict:
    """Read the local file header and return offsets and raw fields."""
    offset = int(info.header_offset)
    if offset < 0 or offset + 30 > file_size:
        raise ExtractError("ZIP 本地文件头偏移无效。")

    raw = _read_at(fh, offset, 30)
    sig = _u32(raw, 0)
    if sig != LOCAL_SIG:
        raise ExtractError("未找到 ZIP 本地文件头，压缩包可能已损坏或是分卷压缩包。")

    version = _u16(raw, 4) & 0xFF
    flags = _u16(raw, 6)
    method = _u16(raw, 8)
    last_time = _u16(raw, 10)
    crc = _u32(raw, 14)
    comp_size = _u32(raw, 18)
    uncomp_size = _u32(raw, 22)
    name_len = _u16(raw, 26)
    extra_len = _u16(raw, 28)

    header_extra = _read_at(fh, offset + 30 + name_len, extra_len)
    data_off = offset + 30 + name_len + extra_len

    # The central directory is authoritative and also resolves ZIP64 values
    # and data-descriptor entries (whose local sizes may be zero/0xffffffff).
    comp_size = int(info.compress_size)
    uncomp_size = int(info.file_size)
    crc = int(info.CRC)

    return {
        "version": version,
        "flags": flags,
        "method": method,
        "last_time": last_time,
        "crc": crc,
        "comp_size": comp_size,
        "uncomp_size": uncomp_size,
        "name_len": name_len,
        "extra_len": extra_len,
        "extra": header_extra,
        "data_off": data_off,
        "header_offset": offset,
        "data_offset_relative": 30 + name_len + extra_len,
    }


def _legacy_hash(fh, info: zipfile.ZipInfo, local: dict, file_size: int) -> ExtractedHash:
    method = local["method"]
    if method not in (0, 8):
        raise ExtractError(
            f"ZIP 文件使用了压缩算法 {method}，hashcat 的 PKZIP 模式只支持存储(0)和 Deflate(8)。",
            "可先用 7-Zip 将压缩包重新打包为 Deflate 压缩后再试。",
        )

    comp_size = int(local["comp_size"])
    if comp_size < 12:
        raise ExtractError("加密数据长度异常（小于 12 字节）。")

    if comp_size > _LEGACY_MAX_DATA:
        raise ExtractError(
            f"加密条目的密文有 {comp_size:,} 字节，超过 hashcat PKZIP 模式的 320 KB 上限。",
            "hashcat 无法只凭部分密文验证这个 ZIP。请尝试压缩包内更小的加密文件，"
            "或先用 7-Zip 解压/重新打包，或改用 bkcrack 等工具。",
        )

    payload = _read_at(fh, int(local["data_off"]), comp_size)

    version = int(local["version"])
    flags = int(local["flags"])
    crc = int(local["crc"])
    check_bytes = 1 if version >= 20 else 2

    # ZipCrypto's 12th header byte is checked against either the high word of
    # the CRC or (when a data descriptor is used) the high word of the DOS
    # timestamp.  Hashcat stores both candidates for fast rejection.
    if flags & 0x08:
        cs = f"{(local['last_time'] >> 8) & 0xFF:02x}{local['last_time'] & 0xFF:02x}"
    else:
        cs = f"{(crc >> 24) & 0xFF:02x}{(crc >> 16) & 0xFF:02x}"
    tc = f"{int(local['last_time']) & 0xFFFF:04x}"

    mode = 17210 if method == 0 else 17200
    line = (
        f"$pkzip2$1*{check_bytes}*2*0*{comp_size:x}*{int(local['uncomp_size']):x}"
        f"*{crc:08x}*0*{int(local['data_offset_relative']):x}*{method:x}"
        f"*{comp_size:x}*{cs}*{tc}*{payload.hex()}*$/pkzip2$"
    )

    return ExtractedHash(
        mode=mode,
        hash_line=line,
        kind="zip",
        label="ZIP · ZipCrypto",
        entry=info.filename,
        detail=(
            f"加密文件：{info.filename} · 压缩后 {comp_size:,} 字节 · "
            f"原始 {int(local['uncomp_size']):,} 字节"
        ),
    )


def _aes_hash(fh, info: zipfile.ZipInfo, local: dict) -> ExtractedHash:
    fields = dict(_parse_extra_fields(local["extra"]))
    aes = fields.get(_AES_EXTRA_ID)
    if aes is None or len(aes) < 7:
        raise ExtractError("检测到 AES 加密，但缺少 0x9901 扩展字段。")

    vendor_version = _u16(aes, 0)
    vendor = aes[2:4]
    strength = aes[4]
    actual_method = _u16(aes, 5)
    if vendor != b"AE" or strength not in (1, 2, 3):
        raise ExtractError("WinZip AES 扩展字段格式不受支持。")
    if actual_method not in (0, 8):
        raise ExtractError(
            f"AES 内部压缩算法 {actual_method} 不受支持（仅支持存储/Deflate）。"
        )

    comp_size = int(local["comp_size"])
    salt_len = 4 + 4 * strength
    overhead = salt_len + 2 + 10
    if comp_size <= overhead:
        raise ExtractError("AES 加密数据长度异常。")

    data_len = comp_size - overhead
    if data_len > _AES_MAX_DATA:
        raise ExtractError(
            f"AES 密文有 {data_len:,} 字节，超过 hashcat 的 8 MB 缓冲上限。",
            "请尝试压缩包内更小的加密文件，或先解压/重新打包。",
        )
    blob = _read_at(fh, int(local["data_off"]), comp_size)
    salt = blob[:salt_len]
    verifier = blob[salt_len : salt_len + 2]
    cipher = blob[salt_len + 2 : salt_len + 2 + data_len]
    auth = blob[salt_len + 2 + data_len : salt_len + 2 + data_len + 10]

    line = (
        f"$zip2$*0*{strength}*0*{salt.hex()}*{verifier.hex()}*{data_len:x}"
        f"*{cipher.hex()}*{auth.hex()}*$/zip2$"
    )
    bits = {1: 128, 2: 192, 3: 256}[strength]
    return ExtractedHash(
        mode=13600,
        hash_line=line,
        kind="zip-aes",
        label=f"ZIP · AES-{bits}",
        entry=info.filename,
        detail=(
            f"加密文件：{info.filename} · AES-{bits} · "
            f"密文 {data_len:,} 字节 · AE-{vendor_version}"
        ),
    )


def extract_zip_hash(path: str | Path) -> ExtractedHash:
    path = Path(path)
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise ExtractError(
            "无法解析 ZIP 文件，可能已损坏、分卷或不是标准 ZIP。",
            "如果是 7z/RAR，请确认扩展名与实际格式一致。",
        ) from exc

    encrypted = [i for i in infos if i.flag_bits & 0x01 and not i.is_dir()]
    if not encrypted:
        raise ExtractError(
            "这个 ZIP 没有加密，或只加密了目录项；无需破解。",
            "请确认压缩包确实设置了密码（打开时会提示输入密码）。",
        )

    file_size = path.stat().st_size
    errors: list[str] = []
    # Prefer the smallest AES/legacy entry: shorter ciphertext means a smaller
    # hash file and the same password.
    with path.open("rb") as fh:
        candidates: list[tuple[int, zipfile.ZipInfo, dict]] = []
        for info in encrypted:
            try:
                local = _local_header(fh, info, file_size)
            except ExtractError as exc:
                errors.append(f"{info.filename}: {exc.message}")
                continue
            candidates.append((int(local["comp_size"]), info, local))

        if not candidates:
            raise ExtractError(
                "找到了加密条目，但无法读取其本地文件头。",
                errors[0] if errors else "",
            )

        candidates.sort(key=lambda item: item[0])
        last_error: ExtractError | None = None
        for _, info, local in candidates:
            try:
                if local["method"] == 99:
                    return _aes_hash(fh, info, local)
                return _legacy_hash(fh, info, local, file_size)
            except ExtractError as exc:
                last_error = exc
                continue

    if last_error:
        raise last_error
    raise ExtractError("未能从 ZIP 中提取到可用的哈希。")
