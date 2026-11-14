"""Small hand-rolled widgets used by the main window."""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from . import theme


class Card(tk.Frame):
    def __init__(self, master, padding: int = 16, bg: str = theme.CARD, **kwargs):
        super().__init__(
            master,
            bg=bg,
            highlightbackground=theme.BORDER,
            highlightthickness=1,
            bd=0,
            **kwargs,
        )
        self.inner = tk.Frame(self, bg=bg)
        self.inner.pack(fill="both", expand=True, padx=padding, pady=padding)


class SectionTitle(tk.Frame):
    def __init__(self, master, number: str, title: str, hint: str = "", bg: str = theme.CARD):
        super().__init__(master, bg=bg)
        badge = tk.Label(
            self,
            text=number,
            bg=theme.ACCENT,
            fg="#FFFFFF",
            font=(theme.FONT_MONO, 8, "bold"),
            padx=6,
            pady=2,
        )
        badge.pack(side="left")
        tk.Label(
            self,
            text=title,
            bg=bg,
            fg=theme.TEXT,
            font=theme.CARD_TITLE_FONT,
        ).pack(side="left", padx=(9, 0))
        if hint:
            tk.Label(
                self,
                text=hint,
                bg=bg,
                fg=theme.MUTED,
                font=theme.SMALL_FONT,
            ).pack(side="right")


class FlatButton(tk.Button):
    def __init__(
        self,
        master,
        text: str,
        command: Optional[Callable] = None,
        kind: str = "secondary",
        width: int | None = None,
        **kwargs,
    ):
        self.kind = kind
        self._enabled = True
        palette = {
            "accent": (theme.ACCENT, "#FFFFFF", theme.ACCENT_HOVER, theme.ACCENT),
            "secondary": (theme.CARD_ALT, theme.TEXT, "#202C45", theme.CARD_ALT),
            "ghost": (theme.CARD, theme.TEXT_SOFT, "#1A2336", theme.CARD),
            "danger": (theme.RED_DIM, theme.RED, "#4A222D", theme.RED_DIM),
            "success": (theme.GREEN_DIM, theme.GREEN, "#1D4C3E", theme.GREEN_DIM),
        }
        bg, fg, hover, active = palette.get(kind, palette["secondary"])
        self._bg = bg
        self._hover = hover
        self._fg = fg
        font = kwargs.pop("font", theme.BUTTON_FONT)
        options = dict(
            master=master,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            disabledforeground=theme.MUTED_2,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=font,
            padx=14,
            pady=8,
            **kwargs,
        )
        if width is not None:
            options["width"] = width
        super().__init__(**options)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event=None):
        if self._enabled:
            self.configure(bg=self._hover)

    def _on_leave(self, _event=None):
        if self._enabled:
            self.configure(bg=self._bg if self["state"] != "disabled" else theme.CARD_ALT)

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.configure(
            state="normal" if enabled else "disabled",
            bg=self._bg if enabled else theme.CARD_ALT,
            cursor="hand2" if enabled else "arrow",
        )


class LinkButton(tk.Label):
    def __init__(self, master, text: str, command: Callable, bg: str = theme.CARD, **kwargs):
        super().__init__(
            master,
            text=text,
            bg=bg,
            fg=theme.ACCENT_2,
            font=theme.SMALL_FONT,
            cursor="hand2",
            **kwargs,
        )
        self._command = command
        self.bind("<Button-1>", lambda _e: self._command())
        self.bind("<Enter>", lambda _e: self.configure(fg=theme.TEXT))
        self.bind("<Leave>", lambda _e: self.configure(fg=theme.ACCENT_2))


class Badge(tk.Label):
    def __init__(self, master, text: str, fg: str = theme.ACCENT_2, bg: str = "#1A2440", **kwargs):
        super().__init__(
            master,
            text=text,
            bg=bg,
            fg=fg,
            font=(theme.FONT_MONO, 8, "bold"),
            padx=7,
            pady=3,
            **kwargs,
        )


class Segmented(tk.Frame):
    def __init__(self, master, options: list[tuple[str, str]], command: Callable[[str], None], bg: str = theme.CARD):
        super().__init__(master, bg=bg)
        self._command = command
        self._buttons: dict[str, tk.Button] = {}
        self._value = options[0][0]
        for value, label in options:
            button = tk.Button(
                self,
                text=label,
                command=lambda v=value: self.set(v),
                relief="flat",
                bd=0,
                highlightthickness=0,
                cursor="hand2",
                font=theme.BUTTON_FONT,
                padx=18,
                pady=8,
            )
            button.pack(side="left", padx=(0, 6))
            self._buttons[value] = button
        self.set(self._value)

    def set(self, value: str, notify: bool = True) -> None:
        self._value = value
        for key, button in self._buttons.items():
            if key == value:
                button.configure(bg=theme.ACCENT, fg="#FFFFFF", activebackground=theme.ACCENT_HOVER)
            else:
                button.configure(bg=theme.CARD_ALT, fg=theme.MUTED, activebackground="#202C45")
        if notify:
            self._command(value)

    def get(self) -> str:
        return self._value

    def set_enabled(self, enabled: bool) -> None:
        for button in self._buttons.values():
            button.configure(
                state="normal" if enabled else "disabled",
                cursor="hand2" if enabled else "arrow",
            )


class ProgressRing(tk.Canvas):
    def __init__(self, master, size: int = 148, bg: str = theme.CARD):
        super().__init__(master, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size
        self._percent = 0.0
        self._center = "0%"
        self._caption = "等待开始"
        self._color = theme.ACCENT
        self._draw()

    def set(self, percent: float, caption: str = "", color: str | None = None) -> None:
        self._percent = max(0.0, min(100.0, percent))
        if caption is not None:
            self._caption = caption
        if color:
            self._color = color
        self._center = f"{self._percent:.1f}%" if 0 < self._percent < 100 else f"{int(self._percent)}%"
        self._draw()

    def reset(self) -> None:
        self._percent = 0.0
        self._center = "0%"
        self._caption = "等待开始"
        self._color = theme.ACCENT
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        pad = 10
        width = 9
        box = (pad, pad, self.size - pad, self.size - pad)
        self.create_oval(*box, outline="#1B253A", width=width)
        if self._percent > 0:
            extent = -359.9 * (self._percent / 100.0)
            self.create_arc(
                *box,
                start=90,
                extent=extent,
                style="arc",
                outline=self._color,
                width=width,
            )
        self.create_text(
            self.size / 2,
            self.size / 2 - 9,
            text=self._center,
            fill=theme.TEXT,
            font=(theme.FONT_UI, 20, "bold"),
        )
        self.create_text(
            self.size / 2,
            self.size / 2 + 21,
            text=self._caption,
            fill=theme.MUTED,
            font=theme.SMALL_FONT,
        )


class DropZone(tk.Frame):
    """Clickable file picker that looks like a drop target."""

    def __init__(self, master, command: Callable, bg: str = theme.CARD, height: int = 78):
        super().__init__(
            master,
            bg=theme.CARD_ALT,
            highlightbackground=theme.BORDER,
            highlightthickness=1,
            cursor="hand2",
            height=height,
        )
        self.pack_propagate(False)
        self._command = command
        self._bg = theme.CARD_ALT
        self._hover = "#1B2740"

        self.icon = tk.Label(
            self,
            text="ZIP",
            bg="#202B45",
            fg=theme.ACCENT_2,
            font=(theme.FONT_MONO, 8, "bold"),
            width=5,
            height=2,
        )
        self.icon.pack(side="left", padx=(12, 10), pady=12)
        text_box = tk.Frame(self, bg=self._bg)
        text_box.pack(side="left", fill="both", expand=True)
        self.primary = tk.Label(
            text_box,
            text="点击选择压缩包",
            bg=self._bg,
            fg=theme.TEXT,
            font=(theme.FONT_UI, 10, "bold"),
            anchor="w",
        )
        self.primary.pack(fill="x", pady=(15, 1))
        self.secondary = tk.Label(
            text_box,
            text="支持 .zip / .rar；7z 可改用哈希文件",
            bg=self._bg,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        )
        self.secondary.pack(fill="x")

        self.browse = tk.Label(
            self,
            text="浏览  ›",
            bg=self._bg,
            fg=theme.ACCENT_2,
            font=(theme.FONT_UI, 9, "bold"),
            cursor="hand2",
        )
        self.browse.pack(side="right", padx=14)

        for widget in (self, self.icon, text_box, self.primary, self.secondary, self.browse):
            widget.bind("<Button-1>", self._click)
            widget.bind("<Enter>", self._enter)
            widget.bind("<Leave>", self._leave)

    def _click(self, _event=None):
        self._command()

    def _enter(self, _event=None):
        self.configure(highlightbackground=theme.ACCENT_2, bg=self._hover)
        for widget in (self.icon, self.primary, self.secondary, self.browse):
            try:
                widget.configure(bg=self._hover)
            except tk.TclError:
                pass

    def _leave(self, _event=None):
        self.configure(highlightbackground=theme.BORDER, bg=self._bg)
        for widget in (self.icon, self.primary, self.secondary, self.browse):
            try:
                widget.configure(bg=self._bg)
            except tk.TclError:
                pass

    def set_content(self, primary: str, secondary: str, icon: str = "ZIP") -> None:
        self.primary.configure(text=primary)
        self.secondary.configure(text=secondary)
        self.icon.configure(text=icon)


class Metric(tk.Frame):
    def __init__(self, master, label: str, value: str = "—", bg: str = theme.CARD):
        super().__init__(master, bg=bg)
        tk.Label(
            self,
            text=label,
            bg=bg,
            fg=theme.MUTED,
            font=theme.SMALL_FONT,
            anchor="w",
        ).pack(fill="x")
        self.value = tk.Label(
            self,
            text=value,
            bg=bg,
            fg=theme.TEXT,
            font=(theme.FONT_MONO, 9, "bold"),
            anchor="w",
            justify="left",
            wraplength=180,
        )
        self.value.pack(fill="x", pady=(2, 0))

    def set(self, value: str, color: str | None = None) -> None:
        self.value.configure(text=value, fg=color or theme.TEXT)


def divider(master, bg: str = theme.CARD) -> tk.Frame:
    line = tk.Frame(master, bg=theme.BORDER, height=1)
    line.pack(fill="x", pady=10)
    return line
