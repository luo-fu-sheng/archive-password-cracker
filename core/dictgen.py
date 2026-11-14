"""Generate a personal password dictionary from names, dates and whole strings.

The generator is deliberately deterministic and dependency-free.  It is meant
for recovering access to your own archive, not for harvesting data.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_COMMON_PASSWORDS = [
    "123456",
    "123456789",
    "12345678",
    "1234567",
    "12345",
    "111111",
    "000000",
    "123123",
    "666666",
    "888888",
    "abc123",
    "a123456",
    "123qwe",
    "qwe123",
    "1qaz2wsx",
    "qwerty",
    "qwerty123",
    "asdfgh",
    "zxcvbn",
    "password",
    "passw0rd",
    "p@ssw0rd",
    "admin",
    "admin123",
    "root",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "master",
    "shadow",
    "superman",
    "trustno1",
    "woaini",
    "woaini1314",
    "5201314",
    "1314520",
    "7758521",
    "521521",
    "112233",
    "147258",
    "159357",
    "2580",
    "2024",
    "2025",
    "2026",
]

_SUFFIXES = [
    "123",
    "1234",
    "12345",
    "123456",
    "123456789",
    "520",
    "521",
    "1314",
    "5201314",
    "!",
    "!!",
    "@",
    "#",
    ".",
    "_",
    "2024",
    "2025",
    "2026",
    "!@#",
    "@123",
    "abc",
    "qq",
]

_PREFIXES = ["!", "@", "#"]
_SEPARATORS = [".", "_", "-", "@"]
_MAX_LENGTH = 32
_DEFAULT_LIMIT = 200_000


@dataclass
class InsertionRule:
    """Insert a repeated text at a position, for a range of repeat counts."""

    position: str = "end"  # start / end / after
    index: int = 1          # used by "after"; 1 = after the first character
    text: str = ""
    min_count: int = 1
    max_count: int = 1


@dataclass
class DictInput:
    chinese_name: str = ""
    pinyin: str = ""
    year: int | None = None
    month: int | None = None
    day: int | None = None
    # Each line is an atomic candidate: no splitting, casing or permutations.
    custom_strings: list[str] = field(default_factory=list)
    insertion_rules: list[InsertionRule] = field(default_factory=list)
    include_dates: bool = True
    include_cases: bool = True
    include_suffixes: bool = True
    include_common: bool = True


@dataclass
class DictResult:
    candidates: list[str] = field(default_factory=list)
    truncated: bool = False

    def __len__(self) -> int:
        return len(self.candidates)


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _case_variants(value: str) -> list[str]:
    value = value.strip()
    if not value:
        return []
    variants = [value, value.lower(), value.upper(), value.capitalize()]
    if " " in value:
        variants.append("".join(part.capitalize() for part in value.split()))
    return _dedupe(variants)


def _all_case_variants(value: str, include_cases: bool = True) -> list[str]:
    """Case variants, including every mix for short ASCII pieces.

    Short pieces (up to 8 ASCII letters) get the full 2^N set, so names such
    as "zhangsan" also cover "ZhangSan".  Longer pieces use the common
    lower/upper/capitalize forms to keep the dictionary bounded.
    """
    if not include_cases:
        return [value]
    variants = _case_variants(value)
    positions = [
        i for i, ch in enumerate(value) if ch.isascii() and ch.isalpha()
    ]
    if len(positions) <= 8:
        chars = list(value)
        for mask in range(1 << len(positions)):
            for bit, pos in enumerate(positions):
                chars[pos] = chars[pos].upper() if mask & (1 << bit) else chars[pos].lower()
            variants.append("".join(chars))
    return _dedupe(variants)


def _chinese_variants(name: str) -> list[str]:
    name = name.strip()
    if not name:
        return []
    variants = [name]
    if len(name) >= 2:
        variants.append(name[0])
        variants.append(name[1:])
    if len(name) >= 3:
        variants.append(name[:2])
    return _dedupe(variants)


def _pinyin_variants(raw: str, include_cases: bool) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    tokens = [part for part in re.split(r"[\s._\-]+", raw) if part]
    compact = "".join(tokens)
    variants: list[str] = [compact]
    if len(tokens) > 1:
        variants.extend(tokens)
        variants.append("".join(tokens))
        variants.append(".".join(tokens))
        variants.append("_".join(tokens))
        variants.append("-".join(tokens))
        initials = "".join(token[0] for token in tokens if token)
        if initials:
            variants.append(initials)
    if include_cases:
        case_variants: list[str] = []
        for item in variants:
            case_variants.extend(_case_variants(item))
        variants.extend(case_variants)
    return _dedupe(variants)


def _date_variants(
    year: int | None, month: int | None, day: int | None
) -> list[str]:
    if not (year and month and day):
        return []
    y4 = f"{year:04d}"
    y2 = f"{year % 100:02d}"
    m = f"{month:02d}"
    d = f"{day:02d}"
    return _dedupe(
        [
            y4 + m + d,
            y2 + m + d,
            y4 + m,
            y4,
            y2,
            m + d,
            f"{month}{day}",
            f"{y4}.{m}.{d}",
            f"{y4}-{m}-{d}",
            f"{y4}_{m}_{d}",
            f"{y2}.{m}.{d}",
            f"{y2}-{m}-{d}",
            f"{m}.{d}",
            f"{m}-{d}",
        ]
    )


def _insert_once(value: str, rule: InsertionRule, count: int) -> str:
    if count <= 0 or not rule.text:
        return value
    added = rule.text * count
    if rule.position == "start":
        return added + value
    if rule.position == "after":
        index = max(0, min(len(value), int(rule.index)))
        return value[:index] + added + value[index:]
    return value + added


def _apply_insertions(
    base: list[str], rules: list[InsertionRule], limit: int
) -> tuple[list[str], bool]:
    """Apply insertion rules to each base and to previous rule variants.

    This keeps each rule usable on its own, while also allowing combinations
    such as "prefix + suffix" when more than one rule is configured.
    """
    out: list[str] = []
    seen: set[str] = set()
    truncated = False

    def remember(values: Iterable[str]) -> None:
        nonlocal truncated
        for value in values:
            if value in seen or not value or len(value) > _MAX_LENGTH:
                continue
            seen.add(value)
            out.append(value)
            if len(out) >= limit:
                truncated = True
                return

    remember(base)
    current = list(base)
    for rule in rules:
        if not rule.text or truncated:
            continue
        lo = max(0, min(20, int(rule.min_count)))
        hi = max(0, min(20, int(rule.max_count)))
        if hi < lo:
            lo, hi = hi, lo
        next_values: list[str] = []
        for value in base + current:
            for count in range(lo, hi + 1):
                next_values.append(_insert_once(value, rule, count))
                if len(next_values) >= limit:
                    truncated = True
                    break
            if truncated:
                break
        remember(next_values)
        current = next_values

    return out, truncated


def _add_custom_strings(
    custom_strings: list[str], include_cases: bool, add
) -> bool:
    """Add each line with case variants, then ordered combinations of lines."""
    tokens = _dedupe(custom_strings)
    for token in tokens:
        for variant in _all_case_variants(token, include_cases):
            if not add(variant):
                return False

    for size in range(2, len(tokens) + 1):
        for sequence in itertools.permutations(tokens, size):
            joined = "".join(sequence)
            for variant in _all_case_variants(joined, include_cases):
                if not add(variant):
                    return False
            if size == 2:
                for sep in (".", "_", "-", "@"):
                    for variant in _all_case_variants(sep.join(sequence), include_cases):
                        if not add(variant):
                            return False
            if include_cases:
                if not add("".join(part.capitalize() for part in sequence)):
                    return False
    return True


def generate_candidates(
    data: DictInput, limit: int = _DEFAULT_LIMIT
) -> DictResult:
    candidates: list[str] = []
    seen: set[str] = set()
    truncated = False

    def add(value: str) -> bool:
        nonlocal truncated
        value = value.strip()
        if not value or len(value) > _MAX_LENGTH:
            return True
        if "\n" in value or "\r" in value:
            return True
        if value in seen:
            return True
        seen.add(value)
        candidates.append(value)
        if len(candidates) >= limit:
            truncated = True
            return False
        return True

    names = _dedupe(
        _chinese_variants(data.chinese_name)
        + _pinyin_variants(data.pinyin, data.include_cases)
    )
    dates = _date_variants(data.year, data.month, data.day) if data.include_dates else []
    custom_strings = _dedupe(data.custom_strings)
    has_rules = any(rule.text for rule in data.insertion_rules)

    if not names and not dates and not custom_strings and not data.include_common and not has_rules:
        return DictResult([], False)

    # 1. User-provided lines.  Each line stays whole, but different lines can
    # be combined in any order, and case variants are generated.
    if custom_strings:
        if not _add_custom_strings(custom_strings, data.include_cases, add):
            return DictResult(candidates, truncated)

    # 2. The most common weak passwords: very cheap to try.
    if data.include_common:
        for password in _COMMON_PASSWORDS:
            if not add(password):
                return DictResult(candidates, truncated)

    # 3. Names alone.
    for name in names:
        if not add(name):
            return DictResult(candidates, truncated)

    # 4. Dates and date/year forms.
    for date in dates:
        if not add(date):
            return DictResult(candidates, truncated)

    # 5. Name/date combinations, both directions and common separators.
    for name in names:
        for date in dates:
            if not add(name + date):
                return DictResult(candidates, truncated)
            if not add(date + name):
                return DictResult(candidates, truncated)
            for sep in _SEPARATORS:
                if not add(name + sep + date):
                    return DictResult(candidates, truncated)
                if not add(date + sep + name):
                    return DictResult(candidates, truncated)

    # 6. Names with common suffixes and prefixes.
    if data.include_suffixes:
        for name in names:
            for suffix in _SUFFIXES:
                if not add(name + suffix):
                    return DictResult(candidates, truncated)
            for prefix in _PREFIXES:
                if not add(prefix + name):
                    return DictResult(candidates, truncated)
        for date in dates:
            for suffix in ("123", "123456", "!", "520", "1314"):
                if not add(date + suffix):
                    return DictResult(candidates, truncated)

    # 7. Common weak passwords combined with the personal names.
    if data.include_common:
        for common in _COMMON_PASSWORDS[:24]:
            for name in names[:8]:
                if not add(name + common):
                    return DictResult(candidates, truncated)
                if not add(common + name):
                    return DictResult(candidates, truncated)

    if data.insertion_rules:
        # With every field empty, the insertion rules themselves become the
        # base (for example "!" repeated 1-3 times).
        if not candidates:
            candidates = [""]
        candidates, extra_truncated = _apply_insertions(
            candidates, data.insertion_rules, limit
        )
        truncated = truncated or extra_truncated

    return DictResult(candidates, truncated)


def write_dictionary(path: str | Path, candidates: Iterable[str]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for candidate in candidates:
            candidate = candidate.strip()
            if not candidate or "\n" in candidate or "\r" in candidate:
                continue
            fh.write(candidate + "\n")
            count += 1
    return count
