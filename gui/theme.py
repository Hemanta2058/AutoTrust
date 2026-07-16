"""
gui/theme.py — AutoTrust Design System
=======================================
All colours, fonts, and spacing in one place.
Every widget pulls from here — change a token, retheme the app.

Design direction
----------------
Inspired by automotive HMI dashboards and enterprise security consoles:
deep steel-blue backgrounds, crisp white text, one electric-teal accent.
Zero border-radius on primary cards (precision instrument feel);
soft radius on interactive elements only.
"""

# ── Palette ──────────────────────────────────────────────────────────────────
BG_BASE    = "#0B1120"   # main window — near-black blue
BG_PANEL   = "#131C2E"   # sidebar / card backgrounds
BG_CARD    = "#1A2540"   # raised card surface
BG_INPUT   = "#0F1825"   # entry / text widget fills
BG_HOVER   = "#1E2D4A"   # hover state

ACCENT      = "#00D4FF"  # electric teal — primary accent (used sparingly)
ACCENT_DIM  = "#007FA0"  # muted teal — secondary accent / borders
SUCCESS     = "#22C55E"  # green — valid / success
WARNING     = "#F59E0B"  # amber — warning
DANGER      = "#EF4444"  # red — revoke / error
DANGER_DIM  = "#7F1D1D"  # dark red — danger hover

TEXT_PRIMARY   = "#E8F0FE"  # main readable text
TEXT_SECONDARY = "#7A8EAD"  # labels, captions
TEXT_ACCENT    = "#00D4FF"  # teal text (titles, highlights)
TEXT_SUCCESS   = "#22C55E"
TEXT_DANGER    = "#EF4444"
TEXT_MUTED     = "#3D526A"  # disabled / very secondary

BORDER      = "#1E2D4A"   # card borders
BORDER_ACCENT = "#00D4FF" # focused border

# ── Typography ────────────────────────────────────────────────────────────────
FONT_DISPLAY  = ("Segoe UI", 26, "bold")    # app title
FONT_TITLE    = ("Segoe UI", 14, "bold")    # section headings
FONT_SUBTITLE = ("Segoe UI", 10)            # subtitles / taglines
FONT_BODY     = ("Segoe UI", 10)            # body text
FONT_BODY_B   = ("Segoe UI", 10, "bold")    # bold body
FONT_SMALL    = ("Segoe UI", 9)             # captions / meta
FONT_MONO     = ("Consolas", 9)             # hashes, keys, log
FONT_BTN      = ("Segoe UI", 10, "bold")    # button labels
FONT_NAV      = ("Segoe UI", 10, "bold")    # sidebar nav labels
FONT_STAT_NUM = ("Segoe UI", 28, "bold")    # big dashboard numbers
FONT_STAT_LBL = ("Segoe UI", 9)            # stat card labels

# ── Spacing ───────────────────────────────────────────────────────────────────
PAD_XS  = 4
PAD_SM  = 8
PAD_MD  = 14
PAD_LG  = 20
PAD_XL  = 32

# ── Geometry ──────────────────────────────────────────────────────────────────
SIDEBAR_W    = 220
TOPBAR_H     = 64
STATUSBAR_H  = 28
CARD_RADIUS  = 8    # px — only for elements that use ttk styling
BTN_PADY     = 10
BTN_PADX     = 18

# ── Status badge colours ──────────────────────────────────────────────────────
STATUS_COLOURS = {
    "VALID":    (SUCCESS, "#052e16"),
    "REVOKED":  (DANGER,  "#450a0a"),
    "EXPIRED":  (WARNING, "#451a03"),
    "UNKNOWN":  (TEXT_SECONDARY, BG_CARD),
}
