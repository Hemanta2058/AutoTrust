"""
gui/widgets.py — AutoTrust Reusable Widgets
============================================
Custom Tkinter components that enforce the design system.
All pages import from here — never style inline.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional
from gui import theme as T


# ── Card ─────────────────────────────────────────────────────────────────────

class Card(tk.Frame):
    """A raised panel with an optional title bar."""

    def __init__(self, parent, title: str = "", **kwargs):
        super().__init__(parent, bg=T.BG_CARD,
                         highlightbackground=T.BORDER,
                         highlightthickness=1, **kwargs)
        if title:
            header = tk.Frame(self, bg=T.BG_PANEL)
            header.pack(fill=tk.X)
            tk.Label(header, text=title, font=T.FONT_BODY_B,
                     fg=T.TEXT_ACCENT, bg=T.BG_PANEL,
                     pady=T.PAD_SM, padx=T.PAD_MD).pack(side=tk.LEFT)
            Divider(self).pack(fill=tk.X)

    @property
    def body(self):
        return self


# ── Stat card ─────────────────────────────────────────────────────────────────

class StatCard(tk.Frame):
    """Dashboard KPI card: big number + label + icon."""

    def __init__(self, parent, label: str, value: str,
                 icon: str = "", colour: str = T.ACCENT, **kwargs):
        super().__init__(parent, bg=T.BG_CARD,
                         highlightbackground=colour,
                         highlightthickness=1, **kwargs)
        inner = tk.Frame(self, bg=T.BG_CARD, padx=T.PAD_LG, pady=T.PAD_LG)
        inner.pack(fill=tk.BOTH, expand=True)

        tk.Label(inner, text=icon, font=("Segoe UI Emoji", 22),
                 fg=colour, bg=T.BG_CARD).pack(anchor="w")
        self._val_lbl = tk.Label(inner, text=value, font=T.FONT_STAT_NUM,
                                  fg=colour, bg=T.BG_CARD)
        self._val_lbl.pack(anchor="w")
        tk.Label(inner, text=label, font=T.FONT_STAT_LBL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_CARD).pack(anchor="w")

    def update_value(self, value: str):
        self._val_lbl.config(text=value)


# ── Section heading ───────────────────────────────────────────────────────────

class SectionHeading(tk.Label):
    def __init__(self, parent, text: str, **kwargs):
        super().__init__(parent, text=text, font=T.FONT_TITLE,
                         fg=T.TEXT_PRIMARY, bg=T.BG_BASE, **kwargs)


# ── Divider ───────────────────────────────────────────────────────────────────

class Divider(tk.Frame):
    def __init__(self, parent, colour: str = T.BORDER, **kwargs):
        super().__init__(parent, bg=colour, height=1, **kwargs)


# ── Primary button ────────────────────────────────────────────────────────────

class PrimaryButton(tk.Button):
    def __init__(self, parent, text: str, command: Callable,
                 icon: str = "", width: int = 0, **kwargs):
        label = f"{icon}  {text}" if icon else text
        super().__init__(parent, text=label, font=T.FONT_BTN,
                         bg=T.ACCENT_DIM, fg=T.TEXT_PRIMARY,
                         activebackground=T.ACCENT,
                         activeforeground=T.BG_BASE,
                         relief=tk.FLAT, cursor="hand2",
                         pady=T.BTN_PADY, padx=T.BTN_PADX,
                         width=width, command=command, **kwargs)
        self.bind("<Enter>", lambda _: self.config(bg=T.ACCENT, fg=T.BG_BASE))
        self.bind("<Leave>", lambda _: self.config(bg=T.ACCENT_DIM,
                                                    fg=T.TEXT_PRIMARY))


class DangerButton(tk.Button):
    def __init__(self, parent, text: str, command: Callable,
                 icon: str = "", **kwargs):
        label = f"{icon}  {text}" if icon else text
        super().__init__(parent, text=label, font=T.FONT_BTN,
                         bg=T.DANGER_DIM, fg=T.TEXT_PRIMARY,
                         activebackground=T.DANGER,
                         activeforeground="#fff",
                         relief=tk.FLAT, cursor="hand2",
                         pady=T.BTN_PADY, padx=T.BTN_PADX,
                         command=command, **kwargs)
        self.bind("<Enter>", lambda _: self.config(bg=T.DANGER))
        self.bind("<Leave>", lambda _: self.config(bg=T.DANGER_DIM))


class SecondaryButton(tk.Button):
    def __init__(self, parent, text: str, command: Callable, **kwargs):
        super().__init__(parent, text=text, font=T.FONT_BTN,
                         bg=T.BG_PANEL, fg=T.TEXT_SECONDARY,
                         activebackground=T.BG_HOVER,
                         activeforeground=T.TEXT_PRIMARY,
                         relief=tk.FLAT, cursor="hand2",
                         pady=8, padx=14,
                         command=command, **kwargs)
        self.bind("<Enter>", lambda _: self.config(bg=T.BG_HOVER,
                                                    fg=T.TEXT_PRIMARY))
        self.bind("<Leave>", lambda _: self.config(bg=T.BG_PANEL,
                                                    fg=T.TEXT_SECONDARY))


# ── Labelled entry ────────────────────────────────────────────────────────────

class LabelledEntry(tk.Frame):
    """A label + Entry pair with consistent styling."""

    def __init__(self, parent, label: str, placeholder: str = "",
                 show: str = "", width: int = 36, **kwargs):
        super().__init__(parent, bg=T.BG_BASE, **kwargs)
        tk.Label(self, text=label, font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._var = tk.StringVar()
        self._entry = tk.Entry(self, textvariable=self._var,
                               font=T.FONT_BODY,
                               bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                               insertbackground=T.ACCENT,
                               relief=tk.FLAT,
                               highlightbackground=T.BORDER,
                               highlightcolor=T.ACCENT,
                               highlightthickness=1,
                               show=show, width=width)
        self._entry.pack(fill=tk.X, pady=(2, 0), ipady=6)
        if placeholder:
            self._set_placeholder(placeholder)

    def _set_placeholder(self, text: str):
        self._placeholder = text
        self._entry.insert(0, text)
        self._entry.config(fg=T.TEXT_MUTED)
        self._entry.bind("<FocusIn>",  self._on_focus_in)
        self._entry.bind("<FocusOut>", self._on_focus_out)

    def _on_focus_in(self, _):
        if self._var.get() == self._placeholder:
            self._entry.delete(0, tk.END)
            self._entry.config(fg=T.TEXT_PRIMARY)

    def _on_focus_out(self, _):
        if not self._var.get():
            self._entry.insert(0, self._placeholder)
            self._entry.config(fg=T.TEXT_MUTED)

    def get(self) -> str:
        v = self._var.get()
        return "" if v == getattr(self, "_placeholder", None) else v

    def clear(self):
        self._entry.delete(0, tk.END)


# ── Labelled combobox ─────────────────────────────────────────────────────────

class LabelledCombo(tk.Frame):
    def __init__(self, parent, label: str, values: list, **kwargs):
        super().__init__(parent, bg=T.BG_BASE, **kwargs)
        tk.Label(self, text=label, font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._var = tk.StringVar(value=values[0] if values else "")
        style = ttk.Style()
        style.configure("Auto.TCombobox",
                         fieldbackground=T.BG_INPUT,
                         background=T.BG_PANEL,
                         foreground=T.TEXT_PRIMARY,
                         selectbackground=T.ACCENT_DIM)
        self._combo = ttk.Combobox(self, textvariable=self._var,
                                   values=values, state="readonly",
                                   style="Auto.TCombobox")
        self._combo.pack(fill=tk.X, pady=(2, 0))

    def get(self) -> str:
        return self._var.get()

    def set_values(self, values: list):
        self._combo["values"] = values
        if values:
            self._var.set(values[0])


# ── Status badge ──────────────────────────────────────────────────────────────

class StatusBadge(tk.Label):
    def __init__(self, parent, status: str, **kwargs):
        fg, bg = T.STATUS_COLOURS.get(status, (T.TEXT_SECONDARY, T.BG_CARD))
        super().__init__(parent, text=f" {status} ",
                         font=T.FONT_SMALL, fg=fg, bg=bg,
                         padx=6, pady=2, **kwargs)


# ── Scrollable log ────────────────────────────────────────────────────────────

class ActivityLog(tk.Frame):
    """Scrollable monospaced log panel."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=T.BG_INPUT,
                         highlightbackground=T.BORDER,
                         highlightthickness=1, **kwargs)
        self._text = tk.Text(self, bg=T.BG_INPUT, fg=T.TEXT_SECONDARY,
                             font=T.FONT_MONO, relief=tk.FLAT,
                             state=tk.DISABLED, wrap=tk.WORD,
                             insertbackground=T.ACCENT)
        self._text.tag_config("ok",      foreground=T.SUCCESS)
        self._text.tag_config("err",     foreground=T.DANGER)
        self._text.tag_config("warn",    foreground=T.WARNING)
        self._text.tag_config("accent",  foreground=T.ACCENT)
        self._text.tag_config("muted",   foreground=T.TEXT_MUTED)

        sb = tk.Scrollbar(self, command=self._text.yview,
                          bg=T.BG_PANEL, troughcolor=T.BG_PANEL,
                          relief=tk.FLAT)
        self._text.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    def log(self, text: str, tag: str = ""):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self._text.config(state=tk.NORMAL)
        self._text.insert(tk.END, f"[{ts}] ", "muted")
        self._text.insert(tk.END, text + "\n", tag or "")
        self._text.see(tk.END)
        self._text.config(state=tk.DISABLED)

    def clear(self):
        self._text.config(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.config(state=tk.DISABLED)


# ── Result panel ──────────────────────────────────────────────────────────────

class ResultPanel(tk.Frame):
    """Displays operation output in a bordered box."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=T.BG_INPUT,
                         highlightbackground=T.BORDER,
                         highlightthickness=1, **kwargs)
        self._text = tk.Text(self, bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                             font=T.FONT_MONO, relief=tk.FLAT,
                             state=tk.DISABLED, wrap=tk.WORD,
                             height=6)
        self._text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def set(self, text: str, colour: str = T.TEXT_PRIMARY):
        self._text.config(state=tk.NORMAL, fg=colour)
        self._text.delete("1.0", tk.END)
        self._text.insert(tk.END, text)
        self._text.config(state=tk.DISABLED)

    def clear(self):
        self.set("")


# ── Nav button ────────────────────────────────────────────────────────────────

class NavButton(tk.Button):
    """Sidebar navigation button."""

    def __init__(self, parent, text: str, icon: str,
                 command: Callable, active: bool = False, **kwargs):
        self._active_bg = T.BG_HOVER
        self._idle_bg   = T.BG_PANEL
        bg = self._active_bg if active else self._idle_bg
        fg = T.TEXT_ACCENT if active else T.TEXT_SECONDARY
        super().__init__(parent,
                         text=f"  {icon}  {text}",
                         font=T.FONT_NAV, bg=bg, fg=fg,
                         activebackground=T.BG_HOVER,
                         activeforeground=T.TEXT_PRIMARY,
                         relief=tk.FLAT, anchor="w",
                         cursor="hand2", pady=12, padx=4,
                         command=command, **kwargs)
        self.bind("<Enter>", lambda _: self.config(
            bg=self._active_bg, fg=T.TEXT_PRIMARY))
        self.bind("<Leave>", lambda _: self.config(
            bg=bg, fg=fg))

    def set_active(self, active: bool):
        bg = self._active_bg if active else self._idle_bg
        fg = T.TEXT_ACCENT if active else T.TEXT_SECONDARY
        self.config(bg=bg, fg=fg)


# ── Data table ────────────────────────────────────────────────────────────────

class DataTable(tk.Frame):
    """Lightweight table using a Text widget with tab-stops."""

    def __init__(self, parent, columns: list,
                 col_widths: Optional[list] = None, **kwargs):
        super().__init__(parent, bg=T.BG_INPUT,
                         highlightbackground=T.BORDER,
                         highlightthickness=1, **kwargs)
        self._columns   = columns
        self._col_widths = col_widths or [14] * len(columns)

        self._text = tk.Text(self, bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                             font=T.FONT_MONO, relief=tk.FLAT,
                             state=tk.DISABLED, wrap=tk.NONE)
        self._text.tag_config("header", foreground=T.ACCENT,
                               font=(*T.FONT_MONO[:1], T.FONT_MONO[1], "bold"))
        self._text.tag_config("alt",    background="#111c2e")
        self._text.tag_config("ok",     foreground=T.SUCCESS)
        self._text.tag_config("err",    foreground=T.DANGER)

        xsb = tk.Scrollbar(self, orient=tk.HORIZONTAL,
                            command=self._text.xview)
        ysb = tk.Scrollbar(self, command=self._text.yview)
        self._text.configure(xscrollcommand=xsb.set,
                              yscrollcommand=ysb.set)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._text.pack(fill=tk.BOTH, expand=True)

        self._render_header()

    def _render_header(self):
        self._text.config(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        row = "  ".join(
            c.ljust(w) for c, w in zip(self._columns, self._col_widths)
        )
        self._text.insert(tk.END, row + "\n", "header")
        self._text.insert(tk.END, "─" * 100 + "\n", "header")
        self._text.config(state=tk.DISABLED)

    def load(self, rows: list):
        """rows: list of tuples matching column count."""
        self._text.config(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        # header
        hrow = "  ".join(
            c.ljust(w) for c, w in zip(self._columns, self._col_widths)
        )
        self._text.insert(tk.END, hrow + "\n", "header")
        self._text.insert(tk.END, "─" * 100 + "\n", "header")
        for i, row in enumerate(rows):
            cells = "  ".join(
                str(v).ljust(w) for v, w in zip(row, self._col_widths)
            )
            tag = "alt" if i % 2 else ""
            self._text.insert(tk.END, cells + "\n", tag)
        if not rows:
            self._text.insert(tk.END, "\n  No records found.\n", "")
        self._text.config(state=tk.DISABLED)
