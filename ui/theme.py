"""Colours, fonts and ttk styling for the desktop UI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

BG = "#0A0E17"
BG_SOFT = "#0E1421"
CARD = "#121A2A"
CARD_ALT = "#172136"
BORDER = "#23304A"
BORDER_HOVER = "#38496B"
TEXT = "#EDF1FA"
TEXT_SOFT = "#C3CCDF"
MUTED = "#7F8BA6"
MUTED_2 = "#5E6A84"
ACCENT = "#7C5CFF"
ACCENT_2 = "#5B8CFF"
ACCENT_HOVER = "#9079FF"
GREEN = "#3DDC97"
GREEN_DIM = "#163B31"
RED = "#FF6B81"
RED_DIM = "#3A1B24"
YELLOW = "#F6C453"
YELLOW_DIM = "#3A3018"
CYAN = "#4DD6E8"

FONT_UI = "Microsoft YaHei UI"
FONT_MONO = "Consolas"

TITLE_FONT = (FONT_UI, 19, "bold")
SUBTITLE_FONT = (FONT_UI, 9)
CARD_TITLE_FONT = (FONT_UI, 10, "bold")
BODY_FONT = (FONT_UI, 9)
SMALL_FONT = (FONT_UI, 8)
BUTTON_FONT = (FONT_UI, 9, "bold")
BIG_FONT = (FONT_UI, 26, "bold")
MONO_FONT = (FONT_MONO, 9)
MONO_SMALL = (FONT_MONO, 8)


def configure_styles(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        ".",
        background=BG,
        foreground=TEXT,
        fieldbackground=CARD_ALT,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        font=BODY_FONT,
    )

    style.configure(
        "TEntry",
        fieldbackground=CARD_ALT,
        foreground=TEXT,
        insertcolor=TEXT,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        padding=(8, 7),
    )
    style.map(
        "TEntry",
        bordercolor=[("focus", ACCENT)],
        lightcolor=[("focus", ACCENT)],
        darkcolor=[("focus", ACCENT)],
    )

    style.configure(
        "TCombobox",
        fieldbackground=CARD_ALT,
        background=CARD_ALT,
        foreground=TEXT,
        arrowcolor=MUTED,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        padding=(8, 6),
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", CARD_ALT)],
        foreground=[("readonly", TEXT)],
        bordercolor=[("focus", ACCENT)],
        arrowcolor=[("active", TEXT)],
    )
    root.option_add("*TCombobox*Listbox.background", CARD_ALT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    style.configure(
        "Accent.Horizontal.TProgressbar",
        troughcolor=CARD_ALT,
        background=ACCENT,
        bordercolor=CARD_ALT,
        lightcolor=ACCENT,
        darkcolor=ACCENT,
        thickness=6,
    )
    style.configure(
        "Vertical.TScrollbar",
        background=CARD_ALT,
        troughcolor=BG_SOFT,
        bordercolor=BG_SOFT,
        arrowcolor=MUTED,
        width=10,
    )
    style.map("Vertical.TScrollbar", background=[("active", BORDER_HOVER)])

    style.configure(
        "TCheckbutton",
        background=BG,
        foreground=TEXT_SOFT,
        font=BODY_FONT,
    )
    style.map(
        "TCheckbutton",
        background=[("active", BG)],
        foreground=[("active", TEXT)],
        indicatorcolor=[("selected", ACCENT), ("!selected", CARD_ALT)],
    )
    return style


def mix(c1: str, c2: str, ratio: float) -> str:
    """Linear interpolation between two #rrggbb colours."""
    ratio = max(0.0, min(1.0, ratio))
    a = tuple(int(c1[i : i + 2], 16) for i in (1, 3, 5))
    b = tuple(int(c2[i : i + 2], 16) for i in (1, 3, 5))
    out = tuple(round(x + (y - x) * ratio) for x, y in zip(a, b))
    return "#%02x%02x%02x" % out
