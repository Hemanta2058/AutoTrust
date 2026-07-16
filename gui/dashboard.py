"""
gui/dashboard.py — AutoTrust Main Application Shell
=====================================================
Renders the top-level window:
  • Fixed sidebar with navigation buttons
  • Top bar with title + live CA status
  • Content area (swapped by nav — each page is a Frame)
  • Bottom status bar

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import tkinter as tk
from datetime import datetime
from typing import Dict, Type

import config
import database
from ca import CertificateAuthority
from gui import theme as T
from gui.widgets import (ActivityLog, Divider, NavButton,
                          StatCard, StatusBadge)

# Pages are imported lazily to keep this file clean
from gui.pages.overview   import OverviewPage
from gui.pages.register   import RegisterPage
from gui.pages.certificate import CertificatePage
from gui.pages.sign       import SignPage
from gui.pages.verify     import VerifyPage
from gui.pages.encrypt    import EncryptPage
from gui.pages.revoke     import RevokePage
from gui.pages.log_page   import LogPage


# ── Nav items ─────────────────────────────────────────────────────────────────
NAV_ITEMS = [
    ("Overview",     "🏠", OverviewPage),
    ("Register",     "🚗", RegisterPage),
    ("Certificate",  "📜", CertificatePage),
    ("Sign",         "✍️",  SignPage),
    ("Verify",       "🔍", VerifyPage),
    ("Encrypt",      "🔒", EncryptPage),
    ("Revoke",       "❌", RevokePage),
    ("Audit Log",    "📋", LogPage),
]


class AutoTrustApp(tk.Tk):
    """Top-level application window."""

    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_TITLE}  —  {config.APP_TAGLINE}")
        self.geometry("1200x760")
        self.minsize(1000, 680)
        self.configure(bg=T.BG_BASE)
        self.resizable(True, True)

        # Shared state passed to every page
        self.ca      = CertificateAuthority()
        self.ca.initialise()
        self.log     = ActivityLog   # shared log widget (set after build)
        self._pages: Dict[str, tk.Frame] = {}
        self._nav_btns: Dict[str, NavButton] = {}
        self._active_page: str = ""

        self._build_ui()
        self._navigate("Overview")

        # Refresh stats every 10 s
        self._refresh_stats()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Top accent stripe
        tk.Frame(self, bg=T.ACCENT, height=3).pack(fill=tk.X)

        # Top bar
        self._build_topbar()

        # Body row: sidebar + content
        body = tk.Frame(self, bg=T.BG_BASE)
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_content(body)

        # Status bar
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self, bg=T.BG_PANEL, height=T.TOPBAR_H)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        # Left: logo + title
        left = tk.Frame(bar, bg=T.BG_PANEL)
        left.pack(side=tk.LEFT, padx=T.PAD_LG, pady=8)
        tk.Label(left, text="🔐", font=("Segoe UI Emoji", 22),
                 bg=T.BG_PANEL, fg=T.ACCENT).pack(side=tk.LEFT, padx=(0, 8))
        title_col = tk.Frame(left, bg=T.BG_PANEL)
        title_col.pack(side=tk.LEFT)
        tk.Label(title_col, text="AutoTrust", font=T.FONT_DISPLAY,
                 bg=T.BG_PANEL, fg=T.ACCENT).pack(anchor="w")
        tk.Label(title_col, text=config.APP_TAGLINE,
                 font=T.FONT_SUBTITLE, bg=T.BG_PANEL,
                 fg=T.TEXT_SECONDARY).pack(anchor="w")

        # Right: CA status + time
        right = tk.Frame(bar, bg=T.BG_PANEL)
        right.pack(side=tk.RIGHT, padx=T.PAD_LG)
        self._ca_badge = StatusBadge(right, "VALID")
        self._ca_badge.config(text="  CA ONLINE  ")
        self._ca_badge.pack(side=tk.RIGHT, padx=(8, 0))
        tk.Label(right, text="Root CA:", font=T.FONT_SMALL,
                 bg=T.BG_PANEL, fg=T.TEXT_SECONDARY).pack(side=tk.RIGHT)

        self._clock_var = tk.StringVar()
        tk.Label(right, textvariable=self._clock_var,
                 font=T.FONT_MONO, bg=T.BG_PANEL,
                 fg=T.TEXT_MUTED).pack(side=tk.RIGHT, padx=(0, T.PAD_MD))
        self._tick_clock()

        Divider(self).pack(fill=tk.X)

    def _tick_clock(self):
        self._clock_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=T.BG_PANEL,
                           width=T.SIDEBAR_W)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Separator line on right edge
        tk.Frame(sidebar, bg=T.BORDER, width=1).pack(
            side=tk.RIGHT, fill=tk.Y)

        tk.Label(sidebar, text="NAVIGATION", font=T.FONT_SMALL,
                 fg=T.TEXT_MUTED, bg=T.BG_PANEL,
                 pady=12).pack(fill=tk.X, padx=T.PAD_MD)

        for name, icon, page_cls in NAV_ITEMS:
            btn = NavButton(sidebar, name, icon,
                            command=lambda n=name: self._navigate(n),
                            width=T.SIDEBAR_W)
            btn.pack(fill=tk.X)
            self._nav_btns[name] = btn
            self._pages[name] = None  # lazy init

        # Bottom: version
        tk.Label(sidebar, text=f"v{config.APP_VERSION}",
                 font=T.FONT_SMALL, fg=T.TEXT_MUTED,
                 bg=T.BG_PANEL).pack(side=tk.BOTTOM, pady=8)

    def _build_content(self, parent):
        self._content = tk.Frame(parent, bg=T.BG_BASE)
        self._content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=T.BG_PANEL, height=T.STATUSBAR_H)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=T.ACCENT, height=1).pack(fill=tk.X)
        inner = tk.Frame(bar, bg=T.BG_PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=T.PAD_MD)

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(inner, textvariable=self._status_var,
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_PANEL).pack(side=tk.LEFT, pady=4)
        tk.Label(inner, text=f"ST6051CEM Practical Cryptography  |  {config.CA_COMMON_NAME}",
                 font=T.FONT_SMALL, fg=T.TEXT_MUTED,
                 bg=T.BG_PANEL).pack(side=tk.RIGHT, pady=4)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _navigate(self, page_name: str):
        # Deactivate old nav button
        if self._active_page and self._active_page in self._nav_btns:
            self._nav_btns[self._active_page].set_active(False)

        # Lazy-create page
        if self._pages.get(page_name) is None:
            _, _, page_cls = next(
                (x for x in NAV_ITEMS if x[0] == page_name), (None, None, None)
            )
            if page_cls:
                self._pages[page_name] = page_cls(
                    self._content, self.ca, self._set_status
                )

        # Hide all, show target
        for frame in self._pages.values():
            if frame:
                frame.pack_forget()
        self._pages[page_name].pack(fill=tk.BOTH, expand=True)

        # Activate nav button
        self._nav_btns[page_name].set_active(True)
        self._active_page = page_name

        # Call on_show if page implements it
        page = self._pages[page_name]
        if hasattr(page, "on_show"):
            page.on_show()

        self._set_status(f"Viewing: {page_name}")

    def _set_status(self, msg: str):
        self._status_var.set(f"●  {msg}")

    def _refresh_stats(self):
        """Refresh Overview stats periodically."""
        page = self._pages.get("Overview")
        if page and hasattr(page, "refresh"):
            page.refresh()
        self.after(10_000, self._refresh_stats)
