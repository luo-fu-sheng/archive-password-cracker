"""Archive password cracker — a desktop GUI for hashcat.

Run with:  python app.py
"""

from __future__ import annotations

import ctypes
import datetime as dt
import json
import os
import queue
import re
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core.archive import detect_archive, extract_hash
from core.dictgen import (
    DictInput,
    InsertionRule,
    generate_candidates,
    write_dictionary,
)
from core.hash_file import inspect_hash_file
from core.hashcat_backend import HashcatBackend, LocalHashcatBackend
from core.hashcat_runner import AttackConfig, find_hashcat, hashcat_version
from core.models import ArchiveInfo, CrackResult, ExtractedHash, ExtractError
from ui import theme
from ui.theme import configure_styles
from ui.widgets import (
    Badge,
    Card,
    DropZone,
    FlatButton,
    LinkButton,
    Metric,
    ProgressRing,
    SectionTitle,
    Segmented,
    divider,
)

APP_NAME = "压缩包密码破解器"
APP_VERSION = "1.0.0"


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _shorten(text: str, limit: int = 54) -> str:
    if len(text) <= limit:
        return text
    keep = max(8, (limit - 3) // 2)
    return text[:keep] + "..." + text[-keep:]


def _format_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"


_BRUTE_CHARSETS: list[tuple[str, str]] = [
    ("数字 0-9", "0123456789"),
    ("小写 a-z", "abcdefghijklmnopqrstuvwxyz"),
    (
        "字母 + 数字",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ),
    (
        "全部可打印字符",
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    ),
]

_MASK_SETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "h": "0123456789abcdef",
    "s": "!@#$%^&*()-_+=[]{};:'\",.<>/?\\|`~",
}
_MASK_SETS["a"] = _MASK_SETS["l"] + _MASK_SETS["u"] + _MASK_SETS["d"] + _MASK_SETS["s"]


def _var_int(var: tk.IntVar, default: int) -> int:
    try:
        return int(var.get())
    except (ValueError, tk.TclError):
        return default


def _mask_choices(mask: str) -> list[str] | None:
    choices: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch != "?":
            choices.append(ch)
            i += 1
            continue
        if i + 1 >= len(mask):
            return None
        code = mask[i + 1]
        if code == "?":
            choices.append("?")
        elif code in _MASK_SETS:
            choices.append(_MASK_SETS[code])
        else:
            return None
        i += 2
    return choices


def _mask_keyspace(mask: str) -> int | None:
    choices = _mask_choices(mask)
    if choices is None:
        return None
    total = 1
    for choice in choices:
        total *= max(1, len(choice))
        if total > 2_000_000:
            return total
    return total


def _write_mask_candidates(mask: str, path: Path, limit: int = 1_000_000) -> int:
    import itertools

    choices = _mask_choices(mask)
    if choices is None:
        raise ValueError("unsupported mask")
    keyspace = 1
    for choice in choices:
        keyspace *= max(1, len(choice))
    if keyspace > limit:
        raise ValueError("mask too large")
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for parts in itertools.product(*choices):
            fh.write("".join(parts) + "\n")
            count += 1
    return count


def _round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kwargs):
    points = [
        x1 + r, y1,
        x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2,
        x1 + r, y2, x1, y2, x1, y2 - r,
        x1, y1 + r, x1, y1, x1 + r, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


class App(tk.Tk):
    def __init__(
        self,
        initial_archive: str | None = None,
        initial_wordlist: str | None = None,
        initial_hash: str | None = None,
        auto_start: bool = False,
    ) -> None:
        _enable_dpi_awareness()
        super().__init__()
        self.withdraw()
        self.title(f"{APP_NAME} · hashcat")
        self.configure(bg=theme.BG)
        self.minsize(1040, 760)
        configure_styles(self)

        self.root_dir = Path(__file__).resolve().parent
        try:
            self.iconbitmap(default=str(self.root_dir / "assets" / "app.ico"))
        except tk.TclError:
            pass
        self.data_dir = self.root_dir / "data"
        self.hash_dir = self.data_dir / "hashes"
        self.result_dir = self.data_dir / "results"
        self.session_dir = self.data_dir / "sessions"
        for folder in (self.data_dir, self.hash_dir, self.result_dir, self.session_dir):
            folder.mkdir(parents=True, exist_ok=True)
        self.config_path = self.data_dir / "config.json"
        self.potfile = self.data_dir / "potfile.txt"
        self._config = self._load_config()

        self.hashcat = find_hashcat(self._config.get("hashcat_path") or None)
        self.hc_version = hashcat_version(self.hashcat) if self.hashcat else "未找到"

        self.events: queue.Queue = queue.Queue()
        self.info: ArchiveInfo | None = None
        self.hash_extract: ExtractedHash | None = None
        self.backend: HashcatBackend | None = None
        self.current_hash: ExtractedHash | None = None
        self.current_hash_path: Path | None = None
        self.session_name = ""
        self.state = "idle"
        self._inputs_enabled = True
        self._hash_mode = False
        self._result_saved_to: Path | None = None
        self._started_at = 0.0
        self._last_status: dict = {}
        self._temp_mask_file: Path | None = None

        self._build_ui()
        self._apply_config_to_ui()
        self._set_state("idle")
        self._center_window()
        self.deiconify()
        self.after(80, self._poll_events)

        if not self.hashcat:
            self.after(300, self._warn_no_hashcat)

        if initial_archive:
            self.after(250, lambda: self._select_archive(Path(initial_archive)))
        if initial_hash:
            self.after(280, lambda: self._load_hash_path(Path(initial_hash)))
        if initial_wordlist:
            self.wordlist_var.set(str(Path(initial_wordlist).resolve()))
            self.attack_mode = "wordlist"
            self.segmented.set("wordlist", notify=False)
            self._show_attack_panel("wordlist")
            self.after(260, self._refresh_wordlist_hint)
        if auto_start:
            self.after(900, self._start_clicked)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def _load_config(self) -> dict:
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}

    def _save_config(self) -> None:
        data = dict(self._config)
        data.update(
            {
                "archive": str(self.info.path) if self.info else "",
                "wordlist": self.wordlist_var.get().strip() if hasattr(self, "wordlist_var") else "",
                "attack": self.attack_mode if hasattr(self, "attack_mode") else "wordlist",
                "mask": self.mask_var.get().strip() if hasattr(self, "mask_var") else "?d?d?d?d?d?d",
                "workload": self.workload_combo.current() if hasattr(self, "workload_combo") else 1,
                "auto_copy": bool(self.auto_copy.get()) if hasattr(self, "auto_copy") else True,
                "brute_charset": self.brute_charset_combo.current()
                if hasattr(self, "brute_charset_combo")
                else 3,
                "brute_min": _var_int(self.brute_min_var, 1)
                if hasattr(self, "brute_min_var")
                else 1,
                "brute_max": _var_int(self.brute_max_var, 6)
                if hasattr(self, "brute_max_var")
                else 6,
                "hashcat_path": self._config.get("hashcat_path", ""),
            }
        )
        try:
            self.config_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass
        self._config = data

    def _apply_config_to_ui(self) -> None:
        wordlist = self._config.get("wordlist", "")
        if wordlist:
            self.wordlist_var.set(wordlist)
            self._refresh_wordlist_hint()
        mask = self._config.get("mask", "")
        if mask:
            self.mask_var.set(mask)
        attack = self._config.get("attack", "wordlist")
        if attack in ("wordlist", "mask", "brute"):
            self.attack_mode = attack
            self.segmented.set(attack, notify=False)
            self._show_attack_panel(attack)
        try:
            self.brute_charset_combo.current(
                max(0, min(3, int(self._config.get("brute_charset", 3))))
            )
            self.brute_min_var.set(max(1, min(12, int(self._config.get("brute_min", 1)))))
            self.brute_max_var.set(max(1, min(12, int(self._config.get("brute_max", 6)))))
            self._update_brute_hint()
        except Exception:
            pass
        try:
            workload = int(self._config.get("workload", 1))
            self.workload_combo.current(max(0, min(3, workload)))
        except Exception:
            self.workload_combo.current(1)
        self.auto_copy.set(bool(self._config.get("auto_copy", True)))

        archive = self._config.get("archive", "")
        if archive and Path(archive).exists():
            try:
                self.info = detect_archive(archive)
                self._display_archive(self.info)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Header / shell
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self._build_header()

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="x", padx=24, pady=(2, 0))
        body.grid_columnconfigure(0, weight=3, minsize=620)
        body.grid_columnconfigure(1, weight=2, minsize=350)

        left = tk.Frame(body, bg=theme.BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        right = tk.Frame(body, bg=theme.BG)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_archive_card(left)
        self._build_attack_card(left)
        self._build_action_row(left)
        self._build_status_card(right)
        self._build_log()
        self._build_footer()

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=24, pady=(18, 12))

        logo = tk.Canvas(header, width=48, height=48, bg=theme.BG, highlightthickness=0)
        logo.pack(side="left")
        _round_rect(logo, 2, 2, 46, 46, 13, fill=theme.ACCENT, outline="")
        logo.create_text(24, 23, text="H", fill="#FFFFFF", font=(theme.FONT_UI, 20, "bold"))
        logo.create_oval(38, 38, 45, 45, fill=theme.GREEN, outline=theme.BG, width=2)

        title_box = tk.Frame(header, bg=theme.BG)
        title_box.pack(side="left", padx=(13, 0))
        tk.Label(
            title_box,
            text=APP_NAME,
            bg=theme.BG,
            fg=theme.TEXT,
            font=theme.TITLE_FONT,
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="ZIP / RAR 密码恢复 · 本地离线 · 不收集任何数据",
            bg=theme.BG,
            fg=theme.MUTED,
            font=theme.SUBTITLE_FONT,
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        right = tk.Frame(header, bg=theme.BG)
        right.pack(side="right")
        self.hc_badge = tk.Label(
            right,
            text=f"hashcat {self.hc_version}",
            bg=theme.CARD_ALT,
            fg=theme.GREEN if self.hashcat else theme.RED,
            font=(theme.FONT_MONO, 8),
            padx=10,
            pady=5,
        )
        self.hc_badge.pack(side="left", padx=(0, 8))
        FlatButton(right, text="使用说明", command=self._show_help, kind="ghost").pack(
            side="left", padx=4
        )
        FlatButton(right, text="设置", command=self._show_settings, kind="ghost").pack(
            side="left", padx=4
        )

    # ------------------------------------------------------------------
    # Left cards
    # ------------------------------------------------------------------
    def _build_archive_card(self, parent: tk.Frame) -> None:
        card = Card(parent)
        card.pack(fill="x")
        SectionTitle(card.inner, "01", "选择压缩包", "ZIP / RAR").pack(fill="x")

        self.dropzone = DropZone(card.inner, command=self._choose_archive)
        self.dropzone.pack(fill="x", pady=(12, 9))

        info_row = tk.Frame(card.inner, bg=theme.CARD)
        info_row.pack(fill="x")
        self.type_badge = Badge(info_row, text="等待选择")
        self.type_badge.pack(side="left")
        self.archive_meta = tk.Label(
            info_row,
            text="尚未选择文件",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        )
        self.archive_meta.pack(side="left", padx=(9, 0), fill="x", expand=True)
        self.hash_link = LinkButton(info_row, text="使用哈希文件 →", command=self._on_hash_link)
        self.hash_link.pack(side="right")

    def _build_attack_card(self, parent: tk.Frame) -> None:
        card = Card(parent)
        card.pack(fill="x", pady=(12, 0))
        SectionTitle(card.inner, "02", "选择破解方式", "字典 / 掩码 / 暴力").pack(fill="x")

        self.attack_body = tk.Frame(card.inner, bg=theme.CARD)
        self.wordlist_panel = tk.Frame(self.attack_body, bg=theme.CARD)
        self.mask_panel = tk.Frame(self.attack_body, bg=theme.CARD)
        self.brute_panel = tk.Frame(self.attack_body, bg=theme.CARD)
        self._build_wordlist_panel(self.wordlist_panel)
        self._build_mask_panel(self.mask_panel)
        self._build_brute_panel(self.brute_panel)
        self.attack_mode = "wordlist"
        self.wordlist_panel.pack(fill="x")

        self.segmented = Segmented(
            card.inner,
            [("wordlist", "字典攻击"), ("mask", "掩码攻击"), ("brute", "暴力破解")],
            command=self._show_attack_panel,
        )
        self.segmented.pack(fill="x", pady=(12, 10))
        self.attack_body.pack(fill="x")

        options = tk.Frame(card.inner, bg=theme.CARD)
        options.pack(fill="x", pady=(12, 0))
        tk.Label(
            options,
            text="性能模式",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        self.workload_combo = ttk.Combobox(
            options,
            values=["节能", "平衡（推荐）", "高性能", "极限"],
            state="readonly",
            width=13,
            font=theme.BODY_FONT,
        )
        self.workload_combo.current(1)
        self.workload_combo.pack(side="left", padx=(8, 18))

        self.auto_copy = tk.BooleanVar(value=True)
        self.auto_copy_check = tk.Checkbutton(
            options,
            text="找到后自动复制密码",
            variable=self.auto_copy,
            bg=theme.CARD,
            fg=theme.TEXT_SOFT,
            activebackground=theme.CARD,
            activeforeground=theme.TEXT,
            selectcolor=theme.CARD_ALT,
            font=theme.SMALL_FONT,
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        )
        self.auto_copy_check.pack(side="right")

    def _build_wordlist_panel(self, panel: tk.Frame) -> None:
        row = tk.Frame(panel, bg=theme.CARD)
        row.pack(fill="x")
        self.wordlist_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(
            row, textvariable=self.wordlist_var, font=theme.BODY_FONT
        )
        self.wordlist_entry.pack(side="left", fill="x", expand=True, ipady=1)
        self.wordlist_browse = FlatButton(
            row, text="选择字典", command=self._choose_wordlist, kind="secondary"
        )
        self.wordlist_browse.pack(side="left", padx=(8, 0))
        self.wordlist_hint = tk.Label(
            panel,
            text="每行一个候选密码；推荐使用常用密码字典或 rockyou.txt",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        )
        self.wordlist_hint.pack(fill="x", pady=(6, 0))
        LinkButton(
            panel,
            text="没有字典？根据姓名 / 生日生成 →",
            command=self._show_dict_generator,
        ).pack(anchor="w", pady=(5, 0))

    def _build_mask_panel(self, panel: tk.Frame) -> None:
        row = tk.Frame(panel, bg=theme.CARD)
        row.pack(fill="x")
        self.mask_var = tk.StringVar(value="?d?d?d?d?d?d")
        self.mask_entry = ttk.Entry(row, textvariable=self.mask_var, font=(theme.FONT_MONO, 10))
        self.mask_entry.pack(side="left", fill="x", expand=True, ipady=1)
        tk.Label(
            row,
            text="掩码",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left", padx=(8, 0))

        chips = tk.Frame(panel, bg=theme.CARD)
        chips.pack(fill="x", pady=(8, 0))
        presets = [
            ("4 位数字", "?d?d?d?d"),
            ("6 位数字", "?d?d?d?d?d?d"),
            ("8 位数字", "?d?d?d?d?d?d?d?d"),
            ("6 位小写", "?l?l?l?l?l?l"),
            ("8 位小写", "?l?l?l?l?l?l?l?l"),
            ("手机号", "1?d?d?d?d?d?d?d?d?d?d"),
        ]
        for label, mask in presets:
            chip = tk.Button(
                chips,
                text=label,
                command=lambda m=mask: self._set_mask(m),
                bg=theme.CARD_ALT,
                fg=theme.TEXT_SOFT,
                activebackground=theme.BORDER,
                activeforeground=theme.TEXT,
                relief="flat",
                bd=0,
                highlightthickness=0,
                cursor="hand2",
                font=theme.SMALL_FONT,
                padx=8,
                pady=4,
            )
            chip.pack(side="left", padx=(0, 6))
        tk.Label(
            panel,
            text="?l 小写  ?u 大写  ?d 数字  ?s 符号  ?a 全部  ·  可自由组合，例如 ?u?l?l?l?d?d",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        ).pack(fill="x", pady=(7, 0))

    def _build_brute_panel(self, panel: tk.Frame) -> None:
        row = tk.Frame(panel, bg=theme.CARD)
        row.pack(fill="x")

        tk.Label(
            row,
            text="字符集",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        self.brute_charset_combo = ttk.Combobox(
            row,
            values=[item[0] for item in _BRUTE_CHARSETS],
            state="readonly",
            width=14,
            font=theme.BODY_FONT,
        )
        self.brute_charset_combo.current(3)
        self.brute_charset_combo.pack(side="left", padx=(7, 16))
        self.brute_charset_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._update_brute_hint()
        )

        tk.Label(
            row,
            text="长度",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        self.brute_min_var = tk.IntVar(value=1)
        self.brute_max_var = tk.IntVar(value=6)
        spin_kwargs = dict(
            from_=1,
            to=12,
            width=4,
            justify="center",
            bg=theme.CARD_ALT,
            fg=theme.TEXT,
            buttonbackground=theme.CARD_ALT,
            insertbackground=theme.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=theme.BORDER,
            highlightcolor=theme.ACCENT,
            font=theme.MONO_SMALL,
            command=self._update_brute_hint,
        )
        self.brute_min_spin = tk.Spinbox(
            row, textvariable=self.brute_min_var, **spin_kwargs
        )
        self.brute_min_spin.pack(side="left", padx=(7, 3))
        self.brute_min_spin.bind("<KeyRelease>", lambda _e: self._update_brute_hint())
        tk.Label(
            row,
            text="至",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        self.brute_max_spin = tk.Spinbox(
            row, textvariable=self.brute_max_var, **spin_kwargs
        )
        self.brute_max_spin.pack(side="left", padx=(3, 3))
        self.brute_max_spin.bind("<KeyRelease>", lambda _e: self._update_brute_hint())
        tk.Label(
            row,
            text="位",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")

        self.brute_hint = tk.Label(
            panel,
            text="",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        )
        self.brute_hint.pack(fill="x", pady=(7, 0))
        tk.Label(
            panel,
            text="无需字典或掩码，程序会从最小长度递增遍历字符集；"
            "压缩包哈希较慢，纯暴力可能耗时极长。",
            bg=theme.CARD,
            fg=theme.YELLOW,
            font=theme.SMALL_FONT,
            anchor="w",
            wraplength=600,
            justify="left",
        ).pack(fill="x", pady=(4, 0))

        self._update_brute_hint()

    def _update_brute_hint(self) -> None:
        if not hasattr(self, "brute_hint"):
            return
        try:
            lo = max(1, min(12, int(self.brute_min_var.get())))
            hi = max(1, min(12, int(self.brute_max_var.get())))
        except (ValueError, tk.TclError):
            self.brute_hint.configure(text="请输入 1–12 之间的长度")
            return
        if hi < lo:
            self.brute_hint.configure(text="最大长度不能小于最小长度", fg=theme.RED)
            return
        charset = _BRUTE_CHARSETS[self.brute_charset_combo.current()][1]
        total = sum(len(charset) ** length for length in range(lo, hi + 1))
        if total >= 10_000_000_000:
            human = f"{total:.2e}"
        elif total >= 100_000_000:
            human = f"{total / 100_000_000:.2f} 亿"
        else:
            human = f"{total:,}"
        self.brute_hint.configure(
            text=f"字符集 {len(charset)} 个 · {lo}–{hi} 位 · 约 {human} 个候选",
            fg=theme.MUTED,
        )

    def _selected_brute_charset(self) -> str:
        return _BRUTE_CHARSETS[self.brute_charset_combo.current()][1]

    def _build_action_row(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg=theme.BG)
        row.pack(fill="x", pady=(14, 0))
        self.start_btn = FlatButton(
            row,
            text="▶   开始破解",
            command=self._start_clicked,
            kind="accent",
            font=(theme.FONT_UI, 11, "bold"),
        )
        self.start_btn.pack(side="left", fill="x", expand=True, ipady=5)
        self.stop_btn = FlatButton(
            row, text="停止", command=self._stop_clicked, kind="danger", width=8
        )
        self.stop_btn.pack(side="left", padx=(10, 0), ipady=5)

    # ------------------------------------------------------------------
    # Right status card
    # ------------------------------------------------------------------
    def _build_status_card(self, parent: tk.Frame) -> None:
        card = Card(parent, padding=18)
        card.pack(fill="both", expand=True)

        top = tk.Frame(card.inner, bg=theme.CARD)
        top.pack(fill="x")
        tk.Label(
            top,
            text="运行状态",
            bg=theme.CARD,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(side="left")
        self.status_badge = Badge(top, text="等待开始", fg=theme.MUTED, bg=theme.CARD_ALT)
        self.status_badge.pack(side="right")

        self.ring = ProgressRing(card.inner, size=150)
        self.ring.pack(pady=(10, 10))

        metrics = tk.Frame(card.inner, bg=theme.CARD)
        metrics.pack(fill="x")
        metrics.grid_columnconfigure(0, weight=1)
        metrics.grid_columnconfigure(1, weight=1)
        self.metric_speed = Metric(metrics, "速度")
        self.metric_speed.grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.metric_mode = Metric(metrics, "哈希模式")
        self.metric_mode.grid(row=0, column=1, sticky="w", pady=(0, 10))
        self.metric_tried = Metric(metrics, "已尝试")
        self.metric_tried.grid(row=1, column=0, sticky="w")
        self.metric_eta = Metric(metrics, "预计剩余")
        self.metric_eta.grid(row=1, column=1, sticky="w")

        divider(card.inner)

        self.message_var = tk.StringVar(
            value="选择一个压缩包，配置字典或掩码后开始。"
        )
        self.message_label = tk.Label(
            card.inner,
            textvariable=self.message_var,
            bg=theme.CARD,
            fg=theme.TEXT_SOFT,
            font=theme.BODY_FONT,
            wraplength=320,
            justify="left",
            anchor="w",
        )
        self.message_label.pack(fill="x")

        self.result_frame = tk.Frame(
            card.inner,
            bg=theme.GREEN_DIM,
            highlightbackground="#1D5C48",
            highlightthickness=1,
        )
        result_head = tk.Frame(self.result_frame, bg=theme.GREEN_DIM)
        result_head.pack(fill="x", padx=10, pady=(9, 0))
        tk.Label(
            result_head,
            text="✓  密码已找到",
            bg=theme.GREEN_DIM,
            fg=theme.GREEN,
            font=theme.BUTTON_FONT,
        ).pack(side="left")
        self.copy_btn = tk.Button(
            result_head,
            text="复制",
            command=self._copy_password,
            bg="#1D5C48",
            fg=theme.GREEN,
            activebackground="#256b55",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=theme.SMALL_FONT,
            padx=9,
            pady=3,
        )
        self.copy_btn.pack(side="right")

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            self.result_frame,
            textvariable=self.password_var,
            bg=theme.GREEN_DIM,
            fg="#D6FFEE",
            readonlybackground=theme.GREEN_DIM,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=(theme.FONT_MONO, 15, "bold"),
        )
        self.password_entry.pack(fill="x", padx=10, pady=(4, 10))
        self.password_entry.configure(state="readonly")

        self.tip_label = tk.Label(
            card.inner,
            text="提示：破解速度取决于显卡性能、密码复杂度和候选字典大小。",
            bg=theme.CARD,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
            wraplength=320,
            justify="left",
            anchor="w",
        )
        self.tip_label.pack(side="bottom", fill="x", pady=(10, 0))

    # ------------------------------------------------------------------
    # Log / footer
    # ------------------------------------------------------------------
    def _build_log(self) -> None:
        card = Card(self, padding=12)
        card.pack(fill="both", expand=True, padx=24, pady=(12, 0))

        head = tk.Frame(card.inner, bg=theme.CARD)
        head.pack(fill="x")
        tk.Label(
            head,
            text="运行日志",
            bg=theme.CARD,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(side="left")
        LinkButton(head, text="打开数据目录", command=self._open_data_dir, bg=theme.CARD).pack(
            side="right", padx=(10, 0)
        )
        LinkButton(head, text="清空", command=self._clear_log, bg=theme.CARD).pack(side="right")

        text_frame = tk.Frame(card.inner, bg="#080C14")
        text_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text = tk.Text(
            text_frame,
            bg="#080C14",
            fg=theme.MUTED,
            insertbackground=theme.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=theme.MONO_SMALL,
            wrap="word",
            padx=9,
            pady=7,
            height=5,
        )
        scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=self.log_text.yview
        )
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.log_text.tag_configure("info", foreground=theme.MUTED)
        self.log_text.tag_configure("cmd", foreground=theme.ACCENT_2)
        self.log_text.tag_configure("success", foreground=theme.GREEN)
        self.log_text.tag_configure("warn", foreground=theme.YELLOW)
        self.log_text.tag_configure("error", foreground=theme.RED)
        self.log_text.configure(state="disabled")

    def _build_footer(self) -> None:
        footer = tk.Frame(self, bg=theme.BG)
        footer.pack(fill="x", padx=24, pady=(8, 10))
        tk.Label(
            footer,
            text="本地离线运行 · 密码不会上传",
            bg=theme.BG,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        tk.Label(
            footer,
            text="仅用于你有权访问的文件",
            bg=theme.BG,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
        ).pack(side="right")

    # ------------------------------------------------------------------
    # Archive / hash selection
    # ------------------------------------------------------------------
    def _choose_archive(self) -> None:
        if not self._inputs_enabled:
            return
        initial = str(self.info.path.parent) if self.info else str(Path.home() / "Downloads")
        path = filedialog.askopenfilename(
            parent=self,
            title="选择要破解的压缩包",
            initialdir=initial,
            filetypes=[
                ("压缩包", "*.zip *.rar *.7z"),
                ("ZIP 压缩包", "*.zip"),
                ("RAR 压缩包", "*.rar"),
                ("所有文件", "*.*"),
            ],
        )
        if path:
            self._select_archive(Path(path))

    def _select_archive(self, path: Path) -> None:
        path = path.resolve()
        self._hash_mode = False
        self.hash_extract = None
        self.current_hash_path = None
        self.info = None
        self.hash_link.configure(text="使用哈希文件 →")
        try:
            info = detect_archive(path)
        except ExtractError as exc:
            self._error(str(exc), exc.hint)
            return
        self.info = info
        self._display_archive(info)
        self._clear_result()
        self.ring.reset()
        self._set_state("idle")
        self.message_var.set(
            "已选择压缩包。点击“开始破解”，程序会先自动提取哈希再调用 hashcat。"
        )
        self._append_log(f"已选择：{path}")
        self._append_log(f"格式识别：{info.label} · {info.detail}")
        if info.kind == "7z":
            self._append_log(
                "提示：7z 需要先通过 7z2hashcat 生成 $7z$ 哈希，可点击“使用哈希文件”载入。",
                "warn",
            )

    def _display_archive(self, info: ArchiveInfo) -> None:
        self.dropzone.set_content(
            _shorten(info.path.name, 46),
            f"{_format_size(info.path.stat().st_size)} · 点击可重新选择",
            "ZIP" if info.kind.startswith("zip") else ("RAR" if info.kind.startswith("rar") else "7Z"),
        )
        self.type_badge.configure(text=info.label)
        detail = info.detail
        if info.kind == "7z":
            detail = "7z 需哈希文件 · 点击下方链接载入"
        self.archive_meta.configure(text=detail)

    def _on_hash_link(self) -> None:
        if self._hash_mode:
            self._choose_archive()
        else:
            self._choose_hash_file()

    def _choose_hash_file(self) -> None:
        if not self._inputs_enabled:
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="选择 hashcat 哈希文件",
            filetypes=[("哈希文件", "*.hash *.txt"), ("所有文件", "*.*")],
        )
        if not path:
            return
        self._load_hash_path(Path(path))

    def _load_hash_path(self, path: Path) -> None:
        try:
            extracted = inspect_hash_file(path)
        except ExtractError as exc:
            self._error(str(exc), exc.hint)
            return

        self._hash_mode = True
        self.info = None
        self.hash_extract = extracted
        self.current_hash_path = Path(path).resolve()
        self.dropzone.set_content(
            _shorten(Path(path).name, 46),
            f"哈希文件 · {extracted.label} · {extracted.mode}",
            "HASH",
        )
        self.type_badge.configure(text="HASH")
        self.archive_meta.configure(
            text=f"模式 {extracted.mode} · {extracted.mode_name}"
        )
        self.hash_link.configure(text="重新选择压缩包 →")
        self._clear_result()
        self.ring.reset()
        self._set_state("idle")
        self.message_var.set(
            "已载入哈希文件。选择字典或掩码后即可开始破解。"
        )
        self._append_log(f"已载入哈希文件：{path}")
        self._append_log(f"识别模式：{extracted.mode} ({extracted.mode_name})")

    # ------------------------------------------------------------------
    # Attack configuration
    # ------------------------------------------------------------------
    def _show_attack_panel(self, mode: str) -> None:
        self.attack_mode = mode
        for panel in (self.wordlist_panel, self.mask_panel, self.brute_panel):
            panel.pack_forget()
        if mode == "wordlist":
            self.wordlist_panel.pack(fill="x")
        elif mode == "brute":
            self.brute_panel.pack(fill="x")
            self._update_brute_hint()
        else:
            self.mask_panel.pack(fill="x")

    def _set_mask(self, mask: str) -> None:
        self.mask_var.set(mask)
        self.mask_entry.focus_set()

    def _choose_wordlist(self) -> None:
        if not self._inputs_enabled:
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="选择密码字典",
            filetypes=[
                ("字典文件", "*.txt *.dict *.lst"),
                ("所有文件", "*.*"),
            ],
        )
        if path:
            self.wordlist_var.set(str(Path(path).resolve()))
            self._refresh_wordlist_hint()

    def _refresh_wordlist_hint(self) -> None:
        raw = self.wordlist_var.get().strip()
        if not raw:
            self.wordlist_hint.configure(
                text="每行一个候选密码；推荐使用常用密码字典或 rockyou.txt",
                fg=theme.MUTED,
            )
            return
        path = Path(raw)
        if not path.exists():
            self.wordlist_hint.configure(text="字典文件不存在", fg=theme.RED)
            return
        self.wordlist_hint.configure(
            text=f"{path.name} · {_format_size(path.stat().st_size)} · 每行一个密码",
            fg=theme.MUTED,
        )

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------
    def _start_clicked(self) -> None:
        if self.state in ("running", "extracting", "stopping"):
            return
        if not self.hashcat:
            self._warn_no_hashcat()
            return

        if self.attack_mode == "wordlist":
            raw = self.wordlist_var.get().strip()
            if not raw:
                self._error("请先选择一个密码字典。", "字典文件每行放一个候选密码。")
                self.wordlist_entry.focus_set()
                return
            if not Path(raw).exists():
                self._error("字典文件不存在。", raw)
                return
        elif self.attack_mode == "brute":
            lo = _var_int(self.brute_min_var, 1)
            hi = _var_int(self.brute_max_var, 6)
            if not (1 <= lo <= 12 and 1 <= hi <= 12):
                self._error("暴力破解长度必须在 1–12 位之间。")
                return
            if hi < lo:
                self._error("最大长度不能小于最小长度。")
                return
            self.brute_min_var.set(lo)
            self.brute_max_var.set(hi)
            self._update_brute_hint()
        else:
            mask = self.mask_var.get().strip()
            if not mask:
                self._error("请填写掩码表达式。", "例如 6 位数字：?d?d?d?d?d?d")
                self.mask_entry.focus_set()
                return
            if not re.fullmatch(r"(?:\?\?|\?[ludsha]|[^?])+", mask):
                self._error(
                    "掩码表达式包含无法识别的占位符。",
                    "可用：?l 小写、?u 大写、?d 数字、?s 符号、?a 全部；"
                    "字面问号请写成 ??。",
                )
                return

        if self._hash_mode:
            if not self.hash_extract or not self.current_hash_path:
                self._error("请先载入哈希文件。")
                return
            self._start_crack(self.hash_extract, source_path=self.current_hash_path)
            return

        if not self.info:
            self._error("请先选择一个压缩包。")
            return
        if self.info.kind == "7z":
            self._error(
                "7z 自动提取暂不可用。",
                "请先用 7z2hashcat 生成 $7z$ 哈希，再点击“使用哈希文件”载入。",
            )
            return

        self._clear_result()
        self._set_state("extracting")
        self._set_badge("提取哈希", theme.YELLOW, theme.YELLOW_DIM)
        self.message_var.set("正在分析压缩包并提取哈希，请稍候……")
        self.ring.set(3, "提取中", theme.YELLOW)
        self._append_log("开始分析压缩包并提取哈希……")
        threading.Thread(
            target=self._extract_worker, args=(self.info,), daemon=True
        ).start()

    def _extract_worker(self, info: ArchiveInfo) -> None:
        try:
            extracted = extract_hash(info)
            self.events.put(("extracted", (info, extracted)))
        except ExtractError as exc:
            self.events.put(("extract_error", exc))
        except Exception as exc:  # defensive: never leave the UI stuck
            self.events.put(("extract_error", ExtractError(f"提取失败：{exc}")))

    def _start_crack(
        self,
        extracted: ExtractedHash,
        source_path: Path | None = None,
    ) -> None:
        if not self.hashcat:
            self._warn_no_hashcat()
            return

        self.current_hash = extracted
        session = time.strftime("crack_%Y%m%d_%H%M%S")
        self.session_name = session
        stem = "hash"
        if self.info:
            stem = re.sub(r"[^\w\-\u4e00-\u9fff]+", "_", self.info.path.stem)[:32] or "archive"
        elif source_path:
            stem = re.sub(r"[^\w\-\u4e00-\u9fff]+", "_", source_path.stem)[:32] or "hash"

        if source_path and source_path.exists():
            hash_path = source_path.resolve()
        else:
            hash_path = self.hash_dir / f"{stem}_{session}.hash"
            hash_path.write_text(extracted.hash_line + "\n", encoding="ascii")

        outfile = self.session_dir / f"{session}.out"
        workload = int(self.workload_combo.current()) + 1  # hashcat -w is 1..4
        effective_mode = 0 if self.attack_mode == "wordlist" else 3
        wordlist = (
            Path(self.wordlist_var.get().strip()).resolve()
            if self.attack_mode == "wordlist"
            else None
        )
        mask_text = self.mask_var.get().strip()
        stdin_candidates = False
        stdin_charset = ""
        stdin_min = 1
        stdin_max = 6

        if self.attack_mode == "brute":
            stdin_candidates = True
            stdin_charset = self._selected_brute_charset()
            stdin_min = _var_int(self.brute_min_var, 1)
            stdin_max = _var_int(self.brute_max_var, 6)
            effective_mode = 0
            wordlist = None
            mask_text = ""
            total = sum(
                len(stdin_charset) ** length
                for length in range(stdin_min, stdin_max + 1)
            )
            self._append_log(
                f"纯暴力：{len(stdin_charset)} 个字符，{stdin_min}–{stdin_max} 位，"
                f"约 {total:,} 个候选。",
                "warn",
            )
            if total > 100_000_000:
                self._append_log(
                    "候选空间很大：压缩包哈希速度通常很低，可能需要很长时间。",
                    "warn",
                )

        # Small masks are expanded to a dictionary.  This is a compatibility
        # path for Intel GPUs whose mask kernel can fail hashcat's self-test;
        # the a0/dictionary kernel is much more widely usable.
        if self.attack_mode == "mask":
            keyspace = _mask_keyspace(mask_text)
            if keyspace is not None and keyspace <= 1_000_000:
                candidate_path = self.session_dir / f"{session}_mask.txt"
                try:
                    count = _write_mask_candidates(mask_text, candidate_path)
                    effective_mode = 0
                    wordlist = candidate_path
                    self._temp_mask_file = candidate_path
                    self._append_log(
                        f"掩码空间 {count:,} 条，已自动展开为临时字典以提高兼容性。",
                        "info",
                    )
                except (OSError, ValueError) as exc:
                    self._append_log(f"掩码展开失败，使用原生掩码：{exc}", "warn")

        config = AttackConfig(
            mode=extracted.mode,
            hash_file=hash_path,
            attack_mode=effective_mode,
            wordlist=wordlist,
            mask=mask_text,
            workload=workload,
            session_name=session,
            stdin_candidates=stdin_candidates,
            stdin_charset=stdin_charset,
            stdin_min=stdin_min,
            stdin_max=stdin_max,
        )

        self._clear_result()
        self._set_state("running")
        self._set_badge("破解中", theme.GREEN, theme.GREEN_DIM)
        self.message_var.set("正在运行 hashcat，首次加载内核可能需要几秒钟。")
        self.ring.set(0, "启动中", theme.ACCENT)
        self.metric_mode.set(f"{extracted.mode} · {extracted.mode_name}")
        self.metric_speed.set("—")
        self.metric_tried.set("—")
        self.metric_eta.set("—")
        self._started_at = time.time()

        self._append_log(f"哈希提取成功：{extracted.label}", "success")
        if extracted.detail:
            self._append_log(extracted.detail)
        for warning in extracted.warnings:
            self._append_log(f"注意：{warning}", "warn")

        self.backend = LocalHashcatBackend(
            self.hashcat.parent,
            self.events,
            self.potfile,
        )
        self.backend.start(config, outfile)

    def _stop_clicked(self) -> None:
        if self.state != "running" or not self.backend:
            return
        self._set_state("stopping")
        self._set_badge("正在停止", theme.YELLOW, theme.YELLOW_DIM)
        self.message_var.set("正在停止 hashcat……")
        self._append_log("用户请求停止。", "warn")
        self.backend.stop()

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------
    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "status":
                    self._update_status(payload)
                elif kind == "extracted":
                    info, extracted = payload
                    self.info = info
                    self._start_crack(extracted)
                elif kind == "extract_error":
                    self._handle_extract_error(payload)
                elif kind == "found":
                    self._show_password(str(payload))
                elif kind == "done":
                    self._finish(payload)
                elif kind == "command":
                    pass
        except queue.Empty:
            pass
        self.after(80, self._poll_events)

    def _update_status(self, status) -> None:
        if self.state != "running":
            return
        self._last_status = {
            "tried": status.tried,
            "total": status.total,
            "speed": status.speed,
        }
        if status.total:
            self.ring.set(status.progress, "破解中", theme.ACCENT)
        if status.speed:
            speed = status.speed.split(" (")[0].strip()
            self.metric_speed.set(speed)
        if status.total:
            self.metric_tried.set(f"{status.tried:,} / {status.total:,}")
        if status.eta:
            self.metric_eta.set(status.eta)
        if self.current_hash:
            self.metric_mode.set(f"{self.current_hash.mode} · {self.current_hash.mode_name}")

    def _handle_extract_error(self, exc: ExtractError) -> None:
        self._set_state("error")
        self._set_badge("提取失败", theme.RED, theme.RED_DIM)
        message = exc.message
        if exc.hint:
            message += "\n" + exc.hint
        self.message_var.set(message)
        self.ring.set(0, "提取失败", theme.RED)
        self._append_log(f"提取失败：{exc.message}", "error")
        if exc.hint:
            self._append_log(exc.hint, "warn")

    def _finish(self, result: CrackResult) -> None:
        self.backend = None
        if self._temp_mask_file:
            try:
                self._temp_mask_file.unlink(missing_ok=True)
            except OSError:
                pass
            self._temp_mask_file = None
        self._set_state("done")
        if result.found:
            self._set_badge("已找到", theme.GREEN, theme.GREEN_DIM)
            self.message_var.set("密码已找到，可点击上方“复制”按钮。")
            self.ring.set(100, "完成", theme.GREEN)
            self.copy_btn.configure(text="复制")
            self._save_result(result.password)
            self._append_log("破解完成：已找到密码。", "success")
            if self.auto_copy.get():
                self._copy_password(silent=True)
        elif result.exit_code == 2:
            self._set_badge("已停止", theme.YELLOW, theme.YELLOW_DIM)
            self.message_var.set(result.message or "已停止破解。")
            self._append_log("任务已停止。", "warn")
        elif result.exit_code < 0 or result.exit_code in (4, 255):
            self._set_badge("运行失败", theme.RED, theme.RED_DIM)
            self.message_var.set(result.message)
            self.ring.set(0, "运行失败", theme.RED)
            self._append_log(result.message, "error")
        else:
            self._set_badge("未找到", theme.MUTED, theme.CARD_ALT)
            self.message_var.set(result.message)
            self.ring.set(100, "已尝试", theme.MUTED)
            self._append_log(result.message, "warn")
        self.start_btn.configure(text="↻   再次破解")

    def _show_password(self, password: str) -> None:
        self.password_var.set(password)
        self.password_entry.configure(state="normal")
        self.password_entry.icursor(0)
        self.password_entry.configure(state="readonly")
        if not self.result_frame.winfo_ismapped():
            self.result_frame.pack(fill="x", pady=(10, 0))
        self._set_badge("已找到", theme.GREEN, theme.GREEN_DIM)
        self.message_var.set("密码已找到，可点击“复制”按钮。")
        self.ring.set(100, "完成", theme.GREEN)
        self.copy_btn.configure(text="复制")
        if self.auto_copy.get():
            self._copy_password(silent=True)

    def _copy_password(self, silent: bool = False) -> None:
        password = self.password_var.get()
        if not password:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update_idletasks()
        except tk.TclError:
            return
        self.copy_btn.configure(text="已复制")
        self.after(1600, lambda: self.copy_btn.configure(text="复制"))
        if not silent:
            self._append_log("密码已复制到剪贴板。", "success")

    def _save_result(self, password: str) -> None:
        if not password:
            return
        stamp = time.strftime("%Y%m%d_%H%M%S")
        stem = "archive"
        target = ""
        if self.info:
            stem = re.sub(r"[^\w\-\u4e00-\u9fff]+", "_", self.info.path.stem)[:40] or "archive"
            target = str(self.info.path)
        elif self.current_hash_path:
            stem = self.current_hash_path.stem[:40]
            target = str(self.current_hash_path)
        path = self.result_dir / f"{stem}_{stamp}.txt"
        lines = [
            f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"目标：{target}",
            f"类型：{self.current_hash.label if self.current_hash else '未知'}",
            f"hashcat 模式：{self.current_hash.mode if self.current_hash else '未知'}",
            f"密码：{password}",
            "",
        ]
        try:
            path.write_text("\n".join(lines), encoding="utf-8")
            self._result_saved_to = path
            self._append_log(f"结果已保存：{path}")
        except OSError as exc:
            self._append_log(f"结果保存失败：{exc}", "warn")

    # ------------------------------------------------------------------
    # UI state helpers
    # ------------------------------------------------------------------
    def _set_state(self, state: str) -> None:
        self.state = state
        running = state in ("running", "extracting", "stopping")
        self._inputs_enabled = not running
        self.dropzone.configure(cursor="arrow" if running else "hand2")
        self.start_btn.set_enabled(not running)
        self.stop_btn.set_enabled(state == "running")
        self.segmented.set_enabled(not running)
        entry_state = "normal" if not running else "disabled"
        self.wordlist_entry.configure(state=entry_state)
        self.mask_entry.configure(state=entry_state)
        self.brute_charset_combo.configure(
            state="readonly" if not running else "disabled"
        )
        self.brute_min_spin.configure(state=entry_state)
        self.brute_max_spin.configure(state=entry_state)
        self.wordlist_browse.set_enabled(not running)
        self.workload_combo.configure(state="readonly" if not running else "disabled")
        if state == "idle":
            self._set_badge("等待开始", theme.MUTED, theme.CARD_ALT)
        elif state == "extracting":
            self._set_badge("提取哈希", theme.YELLOW, theme.YELLOW_DIM)
        elif state == "running":
            self._set_badge("破解中", theme.GREEN, theme.GREEN_DIM)
        elif state == "stopping":
            self._set_badge("正在停止", theme.YELLOW, theme.YELLOW_DIM)
            self.start_btn.set_enabled(False)
            self.stop_btn.set_enabled(False)
        elif state == "done":
            self._set_badge("已完成", theme.MUTED, theme.CARD_ALT)
        elif state == "error":
            self._set_badge("失败", theme.RED, theme.RED_DIM)

    def _set_badge(self, text: str, fg: str, bg: str) -> None:
        self.status_badge.configure(text=text, fg=fg, bg=bg)

    def _clear_result(self) -> None:
        self.password_var.set("")
        if self.result_frame.winfo_ismapped():
            self.result_frame.pack_forget()
        self._result_saved_to = None

    def _error(self, message: str, hint: str = "") -> None:
        self._append_log(message, "error")
        if hint:
            self._append_log(hint, "warn")
        self._set_state("error")
        self._set_badge("需要处理", theme.RED, theme.RED_DIM)
        self.message_var.set(message + (("\n" + hint) if hint else ""))
        self.ring.set(0, "未开始", theme.RED)

    def _warn_no_hashcat(self) -> None:
        messagebox.showerror(
            "未找到 hashcat",
            "没有找到 hashcat.exe。\n\n"
            "请把 hashcat 放在程序目录的 runtime\\hashcat 下，"
            "或在“设置”中指定 hashcat.exe 路径。",
            parent=self,
        )
        self._append_log("未找到 hashcat，请在设置中指定路径。", "error")

    def _append_log(self, text: str, tag: str | None = None) -> None:
        text = str(text).rstrip()
        if not text:
            return
        if tag is None:
            lower = text.lower()
            if "错误" in text or "失败" in text or "error" in lower:
                tag = "error"
            elif "找到" in text or "成功" in text or "完成" in text:
                tag = "success"
            elif "注意" in text or "警告" in text or "提示" in text:
                tag = "warn"
            elif text.startswith("命令") or text.startswith("C:\\"):
                tag = "cmd"
            else:
                tag = "info"
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {text}\n", tag)
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 700:
            self.log_text.delete("1.0", f"{line_count - 700}.0")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _open_data_dir(self) -> None:
        try:
            os.startfile(self.data_dir)
        except OSError as exc:
            self._append_log(f"无法打开目录：{exc}", "warn")

    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------
    def _show_dict_generator(self) -> None:
        if not self._inputs_enabled:
            return

        win = tk.Toplevel(self)
        win.title("根据姓名 / 生日生成字典")
        win.configure(bg=theme.BG)
        win.transient(self)
        win.grab_set()
        win.geometry("780x900")
        win.resizable(False, False)

        header = tk.Frame(win, bg=theme.BG)
        header.pack(fill="x", padx=22, pady=(18, 10))
        tk.Label(
            header,
            text="生成专属密码字典",
            bg=theme.BG,
            fg=theme.TEXT,
            font=(theme.FONT_UI, 15, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="所有字段可留空 · 不同行可组合 · 大小写尝试",
            bg=theme.BG,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="right")

        card = Card(win, padding=18)
        card.pack(fill="both", expand=True, padx=22, pady=(0, 12))
        form = tk.Frame(card.inner, bg=theme.CARD)
        form.pack(fill="x")
        form.grid_columnconfigure(1, weight=1)
        form.grid_columnconfigure(3, weight=1)

        name_var = tk.StringVar()
        pinyin_var = tk.StringVar()
        year_var = tk.StringVar()
        month_var = tk.StringVar()
        day_var = tk.StringVar()

        def label(text: str, row: int, col: int) -> None:
            tk.Label(
                form,
                text=text,
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
                anchor="w",
            ).grid(row=row, column=col, sticky="w", padx=(0, 8), pady=(0, 7))

        label("中文姓名", 0, 0)
        ttk.Entry(form, textvariable=name_var, font=theme.BODY_FONT).grid(
            row=0, column=1, sticky="ew", padx=(0, 18), pady=(0, 7)
        )
        label("拼音 / 英文", 0, 2)
        ttk.Entry(form, textvariable=pinyin_var, font=theme.BODY_FONT).grid(
            row=0, column=3, sticky="ew", pady=(0, 7)
        )

        label("生日", 1, 0)
        birth_row = tk.Frame(form, bg=theme.CARD)
        birth_row.grid(row=1, column=1, columnspan=3, sticky="w", pady=(0, 7))
        for var, unit, width in (
            (year_var, "年", 6),
            (month_var, "月", 4),
            (day_var, "日", 4),
        ):
            ttk.Entry(birth_row, textvariable=var, width=width, font=theme.BODY_FONT).pack(
                side="left", ipady=1
            )
            tk.Label(
                birth_row,
                text=unit,
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            ).pack(side="left", padx=(3, 10))
        tk.Label(
            birth_row,
            text="可留空；支持 1990 年 1 月 1 日这类格式",
            bg=theme.CARD,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
        ).pack(side="left")

        label("常用字符串", 2, 0)
        custom_text = tk.Text(
            form,
            height=4,
            bg=theme.CARD_ALT,
            fg=theme.TEXT,
            insertbackground=theme.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=theme.BORDER,
            highlightcolor=theme.ACCENT,
            font=theme.BODY_FONT,
            padx=7,
            pady=6,
            wrap="none",
        )
        custom_text.grid(
            row=2, column=1, columnspan=3, sticky="ew", pady=(0, 2)
        )
        tk.Label(
            form,
            text="每行保持原样，不在行内拆分；不同行会按任意顺序组合，并尝试大小写变体。",
            bg=theme.CARD,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
            anchor="w",
        ).grid(row=3, column=1, columnspan=3, sticky="w", pady=(0, 7))

        tk.Label(
            card.inner,
            text="中文姓名不会自动转拼音；如需 zhangsan / zs 这类组合，"
            "请在“拼音 / 英文”中填写（可用空格分隔）。",
            bg=theme.CARD,
            fg=theme.MUTED_2,
            font=theme.SMALL_FONT,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        rules_section = tk.Frame(card.inner, bg=theme.CARD)
        rules_section.pack(fill="x", pady=(8, 0))
        rules_head = tk.Frame(rules_section, bg=theme.CARD)
        rules_head.pack(fill="x")
        tk.Label(
            rules_head,
            text="指定位置插入字符（可选）",
            bg=theme.CARD,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(side="left")
        add_rule_btn = FlatButton(
            rules_head, text="+ 添加规则", command=lambda: add_rule(), kind="ghost"
        )
        add_rule_btn.pack(side="right")
        rules_container = tk.Frame(rules_section, bg=theme.CARD)
        rules_container.pack(fill="x", pady=(3, 0))
        rule_rows: list[dict] = []

        spin_style = dict(
            from_=0,
            to=20,
            width=4,
            justify="center",
            bg=theme.CARD_ALT,
            fg=theme.TEXT,
            buttonbackground=theme.CARD_ALT,
            insertbackground=theme.TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=theme.BORDER,
            highlightcolor=theme.ACCENT,
            font=theme.MONO_SMALL,
        )

        def add_rule() -> None:
            if len(rule_rows) >= 4:
                messagebox.showinfo(
                    "规则数量", "最多添加 4 条插入规则。", parent=win
                )
                return
            row = tk.Frame(rules_container, bg=theme.CARD)
            row.pack(fill="x", pady=(2, 0))
            pos_var = tk.StringVar(value="结尾")
            index_var = tk.IntVar(value=1)
            text_var = tk.StringVar()
            min_var = tk.IntVar(value=1)
            max_var = tk.IntVar(value=1)

            tk.Label(
                row,
                text="位置",
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            ).pack(side="left")
            pos_combo = ttk.Combobox(
                row,
                textvariable=pos_var,
                values=["开头", "结尾", "第 N 位后"],
                state="readonly",
                width=9,
                font=theme.SMALL_FONT,
            )
            pos_combo.pack(side="left", padx=(4, 0))
            index_label = tk.Label(
                row,
                text="N=",
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            )
            index_spin = tk.Spinbox(
                row,
                textvariable=index_var,
                from_=1,
                to=40,
                width=3,
                justify="center",
                bg=theme.CARD_ALT,
                fg=theme.TEXT,
                buttonbackground=theme.CARD_ALT,
                insertbackground=theme.TEXT,
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground=theme.BORDER,
                font=theme.MONO_SMALL,
            )
            insert_label = tk.Label(
                row,
                text="插入",
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            )
            insert_label.pack(side="left", padx=(6, 0))
            text_entry = ttk.Entry(
                row, textvariable=text_var, width=12, font=theme.BODY_FONT
            )
            text_entry.pack(side="left", padx=(5, 8))
            tk.Label(
                row,
                text="数量",
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            ).pack(side="left")
            min_spin = tk.Spinbox(row, textvariable=min_var, **spin_style)
            min_spin.pack(side="left", padx=(4, 2))
            tk.Label(
                row,
                text="至",
                bg=theme.CARD,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            ).pack(side="left")
            max_spin = tk.Spinbox(row, textvariable=max_var, **spin_style)
            max_spin.pack(side="left", padx=(2, 8))
            remove_btn = tk.Button(
                row,
                text="删除",
                command=lambda: remove_rule(item),
                bg=theme.CARD,
                fg=theme.RED,
                activebackground=theme.RED_DIM,
                activeforeground=theme.RED,
                relief="flat",
                bd=0,
                highlightthickness=0,
                cursor="hand2",
                font=theme.SMALL_FONT,
            )
            remove_btn.pack(side="right")

            item = {
                "frame": row,
                "position": pos_var,
                "index": index_var,
                "text": text_var,
                "min": min_var,
                "max": max_var,
                "index_spin": index_spin,
                "index_label": index_label,
            }
            rule_rows.append(item)

            def sync_index(_event=None) -> None:
                if pos_var.get() == "第 N 位后":
                    index_spin.configure(state="normal")
                    if not index_label.winfo_ismapped():
                        index_label.pack(
                            side="left", padx=(5, 0), before=insert_label
                        )
                        index_spin.pack(
                            side="left", padx=(2, 0), before=insert_label
                        )
                else:
                    index_spin.configure(state="disabled")
                    index_label.pack_forget()
                    index_spin.pack_forget()

            pos_combo.bind("<<ComboboxSelected>>", sync_index)
            sync_index()

        def remove_rule(item: dict) -> None:
            item["frame"].destroy()
            if item in rule_rows:
                rule_rows.remove(item)

        add_rule()

        def read_rules() -> list:
            result = []
            position_map = {"开头": "start", "结尾": "end", "第 N 位后": "after"}
            for item in rule_rows:
                text = item["text"].get()
                if not text:
                    continue
                try:
                    lo = max(0, min(20, int(item["min"].get())))
                    hi = max(0, min(20, int(item["max"].get())))
                    index = max(1, min(40, int(item["index"].get())))
                except (ValueError, tk.TclError):
                    raise ValueError("插入规则的数量或位置不是有效数字。")
                if hi < lo:
                    raise ValueError("插入规则的最大数量不能小于最小数量。")
                result.append(
                    InsertionRule(
                        position=position_map.get(item["position"].get(), "end"),
                        index=index,
                        text=text,
                        min_count=lo,
                        max_count=hi,
                    )
                )
            return result

        options = tk.Frame(card.inner, bg=theme.CARD)
        options.pack(fill="x", pady=(8, 0))
        include_dates = tk.BooleanVar(value=True)
        include_cases = tk.BooleanVar(value=True)
        include_suffixes = tk.BooleanVar(value=True)
        include_common = tk.BooleanVar(value=True)
        check_opts = dict(
            bg=theme.CARD,
            fg=theme.TEXT_SOFT,
            activebackground=theme.CARD,
            activeforeground=theme.TEXT,
            selectcolor=theme.CARD_ALT,
            font=theme.SMALL_FONT,
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        )
        tk.Checkbutton(
            options, text="加入年份/月日变体", variable=include_dates, **check_opts
        ).pack(side="left", padx=(0, 14))
        tk.Checkbutton(
            options, text="加入大小写变体", variable=include_cases, **check_opts
        ).pack(side="left", padx=(0, 14))
        tk.Checkbutton(
            options, text="加入常见后缀 123/!/@/520", variable=include_suffixes, **check_opts
        ).pack(side="left", padx=(0, 14))
        tk.Checkbutton(
            options, text="加入内置弱密码", variable=include_common, **check_opts
        ).pack(side="left")

        preview_head = tk.Frame(card.inner, bg=theme.CARD)
        preview_head.pack(fill="x", pady=(14, 5))
        tk.Label(
            preview_head,
            text="候选预览",
            bg=theme.CARD,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(side="left")
        preview_label = tk.Label(
            preview_head,
            text="填写后点击“预览”",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        )
        preview_label.pack(side="right")

        preview_text = tk.Text(
            card.inner,
            height=5,
            bg=theme.CARD_ALT,
            fg=theme.TEXT_SOFT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=theme.BORDER,
            font=theme.MONO_SMALL,
            padx=8,
            pady=6,
            wrap="none",
            state="disabled",
        )
        preview_text.pack(fill="both", expand=True)

        def collect() -> DictInput:
            year_text = year_var.get().strip()
            month_text = month_var.get().strip()
            day_text = day_var.get().strip()
            year = month = day = None
            if year_text or month_text or day_text:
                if not (year_text and month_text and day_text):
                    raise ValueError("生日请同时填写年、月、日，或全部留空。")
                try:
                    year, month, day = int(year_text), int(month_text), int(day_text)
                    if not (1900 <= year <= 2100):
                        raise ValueError("年份应在 1900–2100 之间")
                    dt.date(year, month, day)
                except ValueError as exc:
                    raise ValueError(f"生日无效：{exc}") from exc
            name = name_var.get().strip()
            pinyin = pinyin_var.get().strip()
            custom_strings = [
                line.strip()
                for line in custom_text.get("1.0", "end").splitlines()
                if line.strip()
            ]
            return DictInput(
                chinese_name=name,
                pinyin=pinyin,
                year=year,
                month=month,
                day=day,
                custom_strings=custom_strings,
                insertion_rules=read_rules(),
                include_dates=include_dates.get(),
                include_cases=include_cases.get(),
                include_suffixes=include_suffixes.get(),
                include_common=include_common.get(),
            )

        def do_preview() -> None:
            try:
                data = collect()
                result = generate_candidates(data)
            except ValueError as exc:
                messagebox.showwarning("无法生成", str(exc), parent=win)
                return
            if not result.candidates:
                messagebox.showwarning("没有候选", "当前条件没有生成任何密码。", parent=win)
                return
            suffix = "（达到上限，已截断）" if result.truncated else ""
            preview_label.configure(
                text=f"共 {len(result.candidates):,} 条候选 {suffix}",
                fg=theme.GREEN,
            )
            preview_text.configure(state="normal")
            preview_text.delete("1.0", "end")
            preview_text.insert("1.0", "\n".join(result.candidates[:8]))
            preview_text.configure(state="disabled")

        def do_generate() -> None:
            try:
                data = collect()
                result = generate_candidates(data)
            except ValueError as exc:
                messagebox.showwarning("无法生成", str(exc), parent=win)
                return
            if not result.candidates:
                messagebox.showwarning("没有候选", "当前条件没有生成任何密码。", parent=win)
                return

            stem = data.chinese_name or data.pinyin or "custom"
            stem = re.sub(r"[^\w\-\u4e00-\u9fff]+", "_", stem)[:30] or "custom"
            path = self.data_dir / "dicts" / (
                f"{stem}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            )
            try:
                count = write_dictionary(path, result.candidates)
            except OSError as exc:
                messagebox.showerror("保存失败", str(exc), parent=win)
                return

            self.wordlist_var.set(str(path))
            self._refresh_wordlist_hint()
            self.attack_mode = "wordlist"
            self.segmented.set("wordlist", notify=False)
            self._show_attack_panel("wordlist")
            self._clear_result()
            self.ring.reset()
            self._set_state("idle")
            self.start_btn.configure(text="▶   开始破解")
            self.message_var.set(
                f"已生成 {count:,} 条专属密码，并填入字典攻击。点击“开始破解”。"
            )
            self._append_log(f"已生成专属字典：{path}（{count:,} 条）", "success")
            if result.truncated:
                self._append_log("候选超过 20 万条，已截断到上限。", "warn")
            win.destroy()

        buttons = tk.Frame(win, bg=theme.BG)
        buttons.pack(fill="x", padx=22, pady=(0, 18))
        FlatButton(buttons, text="取消", command=win.destroy, kind="ghost").pack(
            side="right"
        )
        FlatButton(
            buttons, text="生成并选用", command=do_generate, kind="accent"
        ).pack(side="right", padx=(0, 8))
        FlatButton(buttons, text="预览", command=do_preview, kind="secondary").pack(
            side="right", padx=(0, 8)
        )

    def _show_help(self) -> None:
        win = tk.Toplevel(self)
        win.title("使用说明")
        win.configure(bg=theme.BG)
        win.transient(self)
        win.grab_set()
        win.geometry("700x580")
        win.resizable(False, False)

        header = tk.Frame(win, bg=theme.BG)
        header.pack(fill="x", padx=22, pady=(18, 8))
        tk.Label(
            header,
            text="使用说明",
            bg=theme.BG,
            fg=theme.TEXT,
            font=(theme.FONT_UI, 15, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="本地离线 · hashcat 驱动",
            bg=theme.BG,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="right")

        body = tk.Frame(win, bg=theme.CARD, highlightbackground=theme.BORDER, highlightthickness=1)
        body.pack(fill="both", expand=True, padx=22, pady=(0, 12))
        text = tk.Text(
            body,
            bg=theme.CARD,
            fg=theme.TEXT_SOFT,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=theme.BODY_FONT,
            wrap="word",
            padx=16,
            pady=14,
            spacing1=2,
            spacing3=6,
        )
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        text.tag_configure("h", foreground=theme.TEXT, font=(theme.FONT_UI, 10, "bold"))
        text.tag_configure("a", foreground=theme.ACCENT_2)
        text.tag_configure("w", foreground=theme.YELLOW)
        content = [
            ("h", "支持的压缩包\n"),
            ("", "• ZIP：传统 ZipCrypto，以及 WinZip AES-128 / AES-192 / AES-256。\n"),
            ("", "• RAR：RAR3（-p / -hp）与 RAR5（-p / -hp）。\n"),
            ("", "• 7z：hashcat 官方包不含 7z2hashcat。请先用 7z2hashcat 生成 $7z$ 哈希，"
             "再点击“使用哈希文件”载入。\n\n"),
            ("h", "三步开始\n"),
            ("", "1. 选择压缩包，程序会自动识别格式并提取 hashcat 哈希。\n"),
            ("", "2. 选择字典攻击、掩码攻击或暴力破解：\n"),
            ("", "   · 字典攻击：每行一个候选密码，适合常见密码、泄漏字典。\n"),
            ("", "   · 掩码攻击：已知长度和字符范围时最快。?d 数字、?l 小写、?u 大写、?s 符号、?a 全部。\n"),
            ("", "   · 暴力破解：只选字符集和长度范围，程序自动从最短到最长逐位遍历，"
             "不需要字典或手写掩码。\n"),
            ("", "   · 没有现成字典：点击字典下方的“根据姓名 / 生日生成”，"
             "填写姓名、拼音、生日和常用字符串即可组合出专属候选；"
             "常用字符串的不同行会任意组合并尝试大小写，"
             "还可以在指定位置插入字符。\n"),
            ("", "3. 点击“开始破解”。进度、速度、预计剩余时间会实时显示。\n\n"),
            ("h", "提高成功率\n"),
            ("", "• 先试常用密码字典，再试掩码，最后才考虑纯暴力。\n"),
            ("", "• 知道大概长度时，掩码比字典更快；纯暴力只适合很短或字符集很小的密码。\n"),
            ("", "• 小掩码会自动展开成临时字典；大掩码若提示“内核自检失败”，"
             "请更新显卡驱动或改用字典。\n"),
            ("", "• 密码越长、字符集越大，耗时呈指数增长。\n"),
            ("", "• ZIP AES 需要完整密文，超大文件的哈希也会较大。\n\n"),
            ("h", "注意\n"),
            ("w", "• 仅可用于你有权访问或恢复的文件。\n"),
            ("", "• 破解使用本机显卡，可能产生较高功耗与温度。\n"),
            ("", "• 程序不会上传压缩包、哈希或密码。\n"),
        ]
        for tag, chunk in content:
            text.insert("end", chunk, tag)
        text.configure(state="disabled")

        FlatButton(win, text="关闭", command=win.destroy, kind="secondary").pack(
            side="right", padx=22, pady=(0, 18)
        )

    def _show_settings(self) -> None:
        win = tk.Toplevel(self)
        win.title("设置")
        win.configure(bg=theme.BG)
        win.transient(self)
        win.grab_set()
        win.geometry("660x360")
        win.resizable(False, False)

        tk.Label(
            win,
            text="设置",
            bg=theme.BG,
            fg=theme.TEXT,
            font=(theme.FONT_UI, 15, "bold"),
        ).pack(anchor="w", padx=22, pady=(18, 10))

        card = Card(win, padding=16)
        card.pack(fill="x", padx=22)
        tk.Label(
            card.inner,
            text="hashcat 可执行文件",
            bg=theme.CARD,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(anchor="w")
        tk.Label(
            card.inner,
            text="可以填 hashcat.exe 的完整路径，或 hashcat 所在文件夹。",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(anchor="w", pady=(4, 8))

        row = tk.Frame(card.inner, bg=theme.CARD)
        row.pack(fill="x")
        path_var = tk.StringVar(
            value=str(self.hashcat) if self.hashcat else self._config.get("hashcat_path", "")
        )
        entry = ttk.Entry(row, textvariable=path_var, font=theme.BODY_FONT)
        entry.pack(side="left", fill="x", expand=True)

        def browse():
            p = filedialog.askopenfilename(
                parent=win,
                title="选择 hashcat.exe",
                filetypes=[("hashcat", "hashcat.exe"), ("所有文件", "*.*")],
            )
            if p:
                path_var.set(p)

        FlatButton(row, text="浏览", command=browse, kind="secondary").pack(
            side="left", padx=(8, 0)
        )

        stats = tk.Frame(card.inner, bg=theme.CARD)
        stats.pack(fill="x", pady=(14, 0))
        tk.Label(
            stats,
            text=f"当前版本：{self.hc_version}",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="left")
        tk.Label(
            stats,
            text=f"结果目录：data\\results",
            bg=theme.CARD,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
        ).pack(side="right")

        def test_path():
            raw = path_var.get().strip()
            if not raw:
                messagebox.showwarning("提示", "请先填写 hashcat 路径。", parent=win)
                return
            p = Path(raw)
            if p.is_dir():
                p = p / "hashcat.exe"
            test_btn.set_enabled(False)
            try:
                version = hashcat_version(p)
                if version == "未知":
                    messagebox.showerror(
                        "测试失败", f"无法运行：{p}\n请确认这是 Windows 版 hashcat。", parent=win
                    )
                else:
                    messagebox.showinfo(
                        "测试成功", f"hashcat 可以运行。\n\n版本：{version}", parent=win
                    )
            finally:
                test_btn.set_enabled(True)

        def clear_pot():
            if messagebox.askyesno(
                "清空结果记录",
                "确定删除 data\\results 下保存的所有密码记录？",
                parent=win,
            ):
                removed = 0
                try:
                    for item in self.result_dir.glob("*.txt"):
                        item.unlink(missing_ok=True)
                        removed += 1
                    self.potfile.unlink(missing_ok=True)
                    messagebox.showinfo(
                        "已清空", f"已删除 {removed} 条结果记录。", parent=win
                    )
                except OSError as exc:
                    messagebox.showerror("清空失败", str(exc), parent=win)

        def save():
            raw = path_var.get().strip()
            p = Path(raw) if raw else None
            if p and p.is_dir():
                p = p / "hashcat.exe"
            if p and not p.exists():
                messagebox.showerror("路径无效", f"找不到：{p}", parent=win)
                return
            if p:
                self.hashcat = p
                self.hc_version = hashcat_version(p)
                self.hc_badge.configure(
                    text=f"hashcat {self.hc_version}",
                    fg=theme.GREEN if self.hc_version != "未知" else theme.RED,
                )
                self._config["hashcat_path"] = str(p)
            self._save_config()
            win.destroy()

        buttons = tk.Frame(win, bg=theme.BG)
        buttons.pack(fill="x", padx=22, pady=(18, 0))
        test_btn = FlatButton(buttons, text="测试路径", command=test_path, kind="secondary")
        test_btn.pack(side="left")
        FlatButton(buttons, text="清空结果记录", command=clear_pot, kind="danger").pack(
            side="left", padx=(8, 0)
        )
        FlatButton(buttons, text="取消", command=win.destroy, kind="ghost").pack(side="right")
        FlatButton(buttons, text="保存", command=save, kind="accent").pack(
            side="right", padx=(0, 8)
        )

    # ------------------------------------------------------------------
    # Window
    # ------------------------------------------------------------------
    def _center_window(self) -> None:
        self.update_idletasks()
        width, height = 1180, 860
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2 - 10)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _on_close(self) -> None:
        if self.state in ("running", "extracting", "stopping"):
            if not messagebox.askyesno(
                "退出",
                "破解任务仍在运行。退出会停止当前任务，确定吗？",
                parent=self,
            ):
                return
            if self.backend:
                self.backend.stop()
                self.backend.join(1.5)
        self._save_config()
        self.destroy()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="压缩包密码破解器")
    parser.add_argument("--archive", help="启动时自动选择的压缩包路径")
    parser.add_argument("--hash", help="启动时自动载入的 hashcat 哈希文件")
    parser.add_argument("--wordlist", help="启动时自动填写的密码字典")
    parser.add_argument("--start", action="store_true", help="启动后自动开始破解")
    args = parser.parse_args()

    app = App(
        initial_archive=args.archive,
        initial_wordlist=args.wordlist,
        initial_hash=args.hash,
        auto_start=args.start,
    )
    app.mainloop()


if __name__ == "__main__":
    main()
