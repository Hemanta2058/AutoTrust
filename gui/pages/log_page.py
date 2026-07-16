"""Audit Log page — full signed_messages table with verification status."""

import tkinter as tk
from gui import theme as T
from gui.widgets import Divider, DataTable, SecondaryButton
import database


class LogPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)

        hrow = tk.Frame(hdr, bg=T.BG_BASE)
        hrow.pack(fill=tk.X)
        tk.Label(hrow, text="Audit Log",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(side=tk.LEFT, anchor="w")
        SecondaryButton(hrow, "↻ Refresh",
                        command=self.on_show).pack(side=tk.RIGHT)

        tk.Label(hdr, text="Immutable record of all signed V2V messages",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_MD)
        body.pack(fill=tk.BOTH, expand=True)

        self._table = DataTable(
            body,
            columns=["Message ID (16)", "Sender", "Recipient",
                     "Verified", "Signed At", "Plaintext (40)"],
            col_widths=[18, 12, 12, 8, 20, 42]
        )
        self._table.pack(fill=tk.BOTH, expand=True)

    def on_show(self):
        rows = database.fetch_all_messages()
        self._table.load([
            (r["message_id"][:16],
             r["sender_id"],
             r["recipient_id"] or "broadcast",
             "✔ YES" if r["is_verified"] else "NO",
             r["signed_at"][:19],
             r["plaintext"][:40])
            for r in rows
        ])
        self._set_status(f"Audit log: {len(rows)} message(s).")
