"""RAR hash extraction for hashcat (RAR 3.x and RAR 5.x).

The parsers below are intentionally read-only.  They never attempt to decrypt
the archive; they only walk the public headers and emit the exact `$RAR3$` /
`$rar5$` lines hashcat expects.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from .models import ExtractedHash, ExtractError

RAR3_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

# RAR3 header flags
R3_ADD_SIZE = 0x8000
R3_ENCRYPTED = 0x0004
R3_SOLID = 0x0010
R3_LARGE = 0x0100
R3_UNICODE = 0x0200
R3_SALT = 0x0400
R3_EXT_TIME = 0x1000
R3_METHOD_STORE = 0x30

# RAR5 block / flag constants
R5_HEAD_MAIN = 1
R5_HEAD_FILE = 2
R5_HEAD_SERVICE = 3
R5_HEAD_CRYPT = 4
R5_HEAD_ENDARC = 5
R5_HFL_EXTRA = 0x0001
R5_HFL_DATA = 0x0002
R5_FHEXTRA_CRYPT = 1
R5_CRYPT_PSWCHECK = 0x01


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _find_magic(data: bytes, magic: bytes) -> int:
    pos = data.find(magic)
    if pos < 0:
        raise ExtractError("未找到 RAR 签名，这个文件不是 RAR 压缩包。")
    return pos


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for i in range(10):
        if pos + i >= len(data):
            raise ExtractError("RAR5 头数据被截断。")
        byte = data[pos + i]
        value |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return value, i + 1
    raise ExtractError("RAR5 变长整数过长。")


# ---------------------------------------------------------------------------
# RAR 3.x
# ---------------------------------------------------------------------------


def _rar3_hp(data: bytes, magic_pos: int) -> ExtractedHash:
    if len(data) < 24:
        raise ExtractError("RAR3 文件太短，无法读取加密尾部。")
    tail = data[-24:]
    salt, block = tail[:8], tail[8:24]
    return ExtractedHash(
        mode=12500,
        hash_line=f"$RAR3$*0*{salt.hex()}*{block.hex()}",
        kind="rar3",
        label="RAR3 · 加密文件头 (-hp)",
        entry="",
        detail="RAR3 加密头模式；需要 hashcat 模式 12500。",
    )


def _decode_rar3_name(raw: bytes, flags: int) -> str:
    if flags & R3_UNICODE and b"\x00" in raw:
        raw = raw.split(b"\x00", 1)[0]
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _extract_rar3(data: bytes, magic_pos: int) -> ExtractedHash:
    body = magic_pos + len(RAR3_MAGIC)
    if body + 7 > len(data):
        raise ExtractError("RAR3 文件头不完整。")

    main_flags = _u16(data, body + 3)
    main_head_size = _u16(data, body + 5)

    if main_flags & 0x0080:
        return _rar3_hp(data, magic_pos)

    if main_head_size < 7:
        raise ExtractError("RAR3 主头长度无效。")

    off = body + main_head_size
    candidates: list[dict] = []

    while off + 7 <= len(data):
        head_type = data[off + 2]
        head_flags = _u16(data, off + 3)
        head_size = _u16(data, off + 5)
        if head_size < 7:
            break

        if head_type != 0x74:  # not a file header
            block_size = head_size
            if head_flags & R3_ADD_SIZE and off + 11 <= len(data):
                block_size += _u32(data, off + 7)
            if block_size <= 0:
                break
            off += block_size
            continue

        if off + 32 > len(data):
            break

        pack_size = _u32(data, off + 7)
        unp_size = _u32(data, off + 11)
        file_crc = data[off + 16 : off + 20]
        method = data[off + 25]
        name_size = _u16(data, off + 26)
        base = 32

        if head_flags & R3_LARGE:
            if off + 40 > len(data):
                break
            pack_size += _u32(data, off + 32) << 32
            unp_size += _u32(data, off + 36) << 32
            base = 40

        name_start = off + base
        if name_start + name_size > len(data):
            break
        raw_name = data[name_start : name_start + name_size]
        name = _decode_rar3_name(raw_name, head_flags)
        pos = name_start + name_size

        salt = b""
        if head_flags & R3_SALT:
            if pos + 8 > len(data):
                break
            salt = data[pos : pos + 8]
            pos += 8

        if head_flags & R3_EXT_TIME:
            # Extended time is part of head_size; move to the data offset.
            pass

        data_off = off + head_size
        if (
            (head_flags & R3_ENCRYPTED)
            and not (head_flags & R3_SOLID)
            and len(salt) == 8
            and method > 0
            and pack_size > 0
            and (pack_size % 16) == 0
            and data_off + pack_size <= len(data)
        ):
            candidates.append(
                {
                    "pack_size": pack_size,
                    "unp_size": unp_size,
                    "crc": file_crc,
                    "method": method,
                    "salt": salt,
                    "name": name,
                    "data_off": data_off,
                }
            )

        off = data_off + pack_size

    if not candidates:
        raise ExtractError(
            "这个 RAR3 中没有找到可用的加密文件。",
            "可能使用了固实压缩、仅加密文件名，或文件未加密。",
        )

    # Stored entries are dramatically faster in hashcat; otherwise pick the
    # smallest ciphertext.  Both reveal the same archive password.
    stored = [c for c in candidates if c["method"] == R3_METHOD_STORE]
    chosen = min(stored or candidates, key=lambda c: (c["pack_size"], c["unp_size"]))
    mode = 23700 if chosen["method"] == R3_METHOD_STORE else 23800
    blob = data[chosen["data_off"] : chosen["data_off"] + chosen["pack_size"]]
    line = (
        f"$RAR3$*1*{chosen['salt'].hex()}*{chosen['crc'].hex()}*"
        f"{chosen['pack_size']}*{chosen['unp_size']}*1*{blob.hex()}*"
        f"{chosen['method']:02x}"
    )
    return ExtractedHash(
        mode=mode,
        hash_line=line,
        kind="rar3",
        label="RAR3 · " + ("存储" if mode == 23700 else "压缩"),
        entry=chosen["name"],
        detail=(
            f"加密文件：{chosen['name']} · 压缩后 {chosen['pack_size']:,} 字节 · "
            f"原始 {chosen['unp_size']:,} 字节"
        ),
    )


# ---------------------------------------------------------------------------
# RAR 5.x
# ---------------------------------------------------------------------------


def _rar5_parse_crypt_fields(data: bytes, pos: int) -> tuple[dict, int]:
    version, n = _read_vint(data, pos)
    pos += n
    flags, n = _read_vint(data, pos)
    pos += n
    if pos >= len(data):
        raise ExtractError("RAR5 加密字段被截断。")
    lg2 = data[pos]
    pos += 1
    if pos + 16 > len(data):
        raise ExtractError("RAR5 加密盐被截断。")
    salt = data[pos : pos + 16]
    pos += 16

    pswcheck = b""
    check_ok = None
    if flags & R5_CRYPT_PSWCHECK:
        if pos + 8 + 4 > len(data):
            raise ExtractError("RAR5 密码校验字段被截断。")
        pswcheck = data[pos : pos + 8]
        stored = data[pos + 8 : pos + 12]
        check_ok = hashlib.sha256(pswcheck).digest()[:4] == stored
        pos += 12

    return {
        "version": version,
        "flags": flags,
        "lg2": lg2,
        "salt": salt,
        "pswcheck": pswcheck,
        "check_ok": check_ok,
    }, pos


def _rar5_hash(crypt: dict, iv: bytes, entry: str, mode_note: str) -> ExtractedHash:
    if len(crypt["salt"]) != 16 or len(crypt["pswcheck"]) != 8:
        raise ExtractError(
            "RAR5 加密头中缺少密码校验数据，hashcat 无法验证该文件。",
            "请改用较新版本的 WinRAR 重新压缩，或使用 John the Ripper 提取。",
        )
    warnings = []
    if crypt["check_ok"] is False:
        warnings.append("RAR5 密码校验字段的 SHA-256 不一致，仍尝试提取。")
    return ExtractedHash(
        mode=13000,
        hash_line=(
            f"$rar5$16${crypt['salt'].hex()}${crypt['lg2']}$"
            f"{iv.hex()}$8${crypt['pswcheck'].hex()}"
        ),
        kind="rar5",
        label="RAR5" + (f" · {mode_note}" if mode_note else ""),
        entry=entry,
        detail=(
            f"PBKDF2 迭代 2^{crypt['lg2']} · "
            f"密码校验 {crypt['pswcheck'].hex()}"
        ),
        warnings=warnings,
    )


def _extract_rar5(data: bytes, magic_pos: int) -> ExtractedHash:
    pos = magic_pos + len(RAR5_MAGIC)
    crypt: dict | None = None
    header_encrypted = False

    while pos < len(data):
        block_start = pos
        if pos + 4 > len(data):
            break
        # header CRC is at block_start; it is not validated here.
        pos += 4
        block_size, n = _read_vint(data, pos)
        pos += n
        header_start = pos  # first byte of header_type
        if pos >= len(data):
            break
        header_type = data[pos]
        pos += 1
        flags, n = _read_vint(data, pos)
        pos += n
        extra_size = 0
        data_size = 0
        if flags & R5_HFL_EXTRA:
            extra_size, n = _read_vint(data, pos)
            pos += n
        if flags & R5_HFL_DATA:
            data_size, n = _read_vint(data, pos)
            pos += n

        # header_size covers header_type..end of extras.  The full block starts
        # at its CRC and includes the variable-length block_size field.
        total_header = (header_start - block_start) + block_size
        next_block = block_start + total_header + data_size

        if header_type == R5_HEAD_CRYPT:
            try:
                crypt, _ = _rar5_parse_crypt_fields(data, pos)
            except ExtractError:
                raise
            header_encrypted = True
            # The encrypted header that follows begins with a 16-byte IV.
            if next_block + 16 > len(data):
                raise ExtractError("RAR5 加密头之后缺少 IV。")
            iv = data[next_block : next_block + 16]
            return _rar5_hash(crypt, iv, "", "加密文件头 (-hp)")

        if header_type in (R5_HEAD_FILE, R5_HEAD_SERVICE):
            file_flags, n = _read_vint(data, pos)
            pos += n
            unp_size, n = _read_vint(data, pos)
            pos += n
            attr, n = _read_vint(data, pos)
            pos += n
            if file_flags & 0x0002:  # FHFL_UTIME
                pos += 4
            crc = b""
            if file_flags & 0x0004:  # FHFL_CRC32
                crc = data[pos : pos + 4]
                pos += 4
            comp_info, n = _read_vint(data, pos)
            pos += n
            host_os, n = _read_vint(data, pos)
            pos += n
            name_size, n = _read_vint(data, pos)
            pos += n
            raw_name = data[pos : pos + name_size]
            pos += name_size
            name = raw_name.decode("utf-8", "replace")

            # Walk the extra area looking for FHEXTRA_CRYPT.
            extra_end = pos + extra_size
            while pos + 1 < extra_end:
                field_size, n = _read_vint(data, pos)
                pos += n
                field_end = pos + field_size
                if field_end > len(data) or field_end > extra_end:
                    break
                field_type, n = _read_vint(data, pos)
                pos += n
                if field_type == R5_FHEXTRA_CRYPT:
                    parsed, _ = _rar5_parse_crypt_fields(data, pos)
                    # File encryption stores the IV inside the crypt record,
                    # after the salt.  Re-parse it explicitly.
                    iv_pos = pos
                    _, n1 = _read_vint(data, iv_pos)
                    iv_pos += n1
                    _, n2 = _read_vint(data, iv_pos)
                    iv_pos += n2
                    iv_pos += 1 + 16
                    iv = data[iv_pos : iv_pos + 16]
                    if len(iv) == 16:
                        return _rar5_hash(parsed, iv, name, "")
                pos = field_end

        if next_block <= block_start:
            break
        pos = next_block

    if header_encrypted:
        raise ExtractError("RAR5 加密文件头解析失败。")
    raise ExtractError(
        "这个 RAR5 中没有找到可用的加密文件。",
        "可能未加密，或使用了 hashcat 暂不支持的固实/特殊加密方式。",
    )


def extract_rar_hash(path: str | Path) -> ExtractedHash:
    path = Path(path)
    data = path.read_bytes()
    if not data:
        raise ExtractError("RAR 文件为空。")

    if data.startswith(RAR5_MAGIC) or RAR5_MAGIC in data[:2 * 1024 * 1024]:
        magic_pos = data.find(RAR5_MAGIC)
        if magic_pos < 0:
            raise ExtractError("未找到 RAR5 签名。")
        return _extract_rar5(data, magic_pos)

    if data.startswith(RAR3_MAGIC) or RAR3_MAGIC in data[:2 * 1024 * 1024]:
        magic_pos = data.find(RAR3_MAGIC)
        if magic_pos < 0:
            raise ExtractError("未找到 RAR3 签名。")
        return _extract_rar3(data, magic_pos)

    raise ExtractError("不是受支持的 RAR 文件（RAR3/RAR5）。")
