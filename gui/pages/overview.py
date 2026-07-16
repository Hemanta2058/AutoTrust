"""Overview / dashboard page — KPI cards + recent activity."""

import tkinter as tk
from gui import theme as T
from gui.widgets import Card, Divider, SectionHeading, StatCard, DataTable
import database


class OverviewPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._stat_cards = {}
        self._build()

    def _build(self):
        # ── Page header ────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Network Overview",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr, text="Live status of the AutoTrust V2V PKI network",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")

        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        # ── KPI cards row ──────────────────────────────────────────────────
        cards_row = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG)
        cards_row.pack(fill=tk.X, padx=T.PAD_XL)

        kpis = [
            ("vehicles",     "Registered Vehicles", "🚗", T.ACCENT),
            ("certificates", "Valid Certificates",  "📜", T.SUCCESS),
            ("revoked",      "Revoked Certs",       "❌", T.DANGER),
            ("messages",     "Signed Messages",     "✍️",  T.WARNING),
        ]
        for key, label, icon, colour in kpis:
            card = StatCard(cards_row, label, "0", icon, colour)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                      padx=(0, T.PAD_SM))
            self._stat_cards[key] = card

        # ── Recent vehicles ────────────────────────────────────────────────
        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL)
        body.pack(fill=tk.BOTH, expand=True, pady=T.PAD_MD)

        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, T.PAD_MD))

        tk.Label(left, text="Recent Vehicles", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._veh_table = DataTable(
            left,
            columns=["Vehicle ID", "Owner", "Type", "Registered"],
            col_widths=[16, 18, 10, 24]
        )
        self._veh_table.pack(fill=tk.BOTH, expand=True)

        # ── Recent certificates ────────────────────────────────────────────
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Recent Certificates", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._cert_table = DataTable(
            right,
            columns=["Serial (short)", "Vehicle", "Status", "Expires"],
            col_widths=[14, 14, 8, 24]
        )
        self._cert_table.pack(fill=tk.BOTH, expand=True)

        self.refresh()

    def refresh(self):
        stats = database.get_stats()
        for key, card in self._stat_cards.items():
            card.update_value(str(stats.get(key, 0)))

        vehs = database.fetch_all_vehicles()
        self._veh_table.load([
            (r["vehicle_id"], r["owner_name"],
             r["vehicle_type"], r["registered_at"][:19])
            for r in vehs[:8]
        ])

        certs = database.fetch_all_certificates()
        self._cert_table.load([
            (r["serial_number"][:12], r["vehicle_id"],
             r["status"], r["expires_at"][:10])
            for r in certs[:8]
        ])

    def on_show(self):
        self.refresh()
