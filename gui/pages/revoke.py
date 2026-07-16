"""Revoke Certificate page — CRL management."""

import tkinter as tk
from tkinter import messagebox
from gui import theme as T
from gui.widgets import (Divider, LabelledEntry, LabelledCombo,
                          DangerButton, ResultPanel, DataTable)
import database


REVOCATION_REASONS = [
    "Key compromise",
    "CA compromise",
    "Affiliation changed",
    "Superseded",
    "Cessation of operation",
    "Certificate hold",
    "Unspecified",
]


class RevokePage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Revoke Certificate",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr,
                 text="Add certificate to the Certificate Revocation List (CRL)",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, T.PAD_XL))

        self._serial = LabelledEntry(left, "Certificate Serial Number",
                                      placeholder="Full serial from Audit Log")
        self._serial.pack(fill=tk.X, pady=T.PAD_SM)

        self._vid = LabelledEntry(left, "Vehicle ID",
                                   placeholder="e.g. VH-A1B2C3D4")
        self._vid.pack(fill=tk.X, pady=T.PAD_SM)

        self._reason = LabelledCombo(left, "Revocation Reason",
                                      REVOCATION_REASONS)
        self._reason.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(left, text="⚠  Revocation is permanent and cannot be undone.",
                 font=T.FONT_SMALL, fg=T.WARNING,
                 bg=T.BG_BASE).pack(anchor="w", pady=T.PAD_SM)

        DangerButton(left, "Revoke Certificate", icon="❌",
                     command=self._revoke).pack(anchor="w", pady=T.PAD_MD)

        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Result", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._result = ResultPanel(right)
        self._result.pack(fill=tk.X, pady=(0, T.PAD_MD))

        tk.Label(right, text="Certificate Revocation List (CRL)",
                 font=T.FONT_BODY_B, fg=T.TEXT_ACCENT,
                 bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._table = DataTable(
            right,
            columns=["Serial (12)", "Vehicle", "Reason", "Revoked At"],
            col_widths=[14, 14, 22, 22]
        )
        self._table.pack(fill=tk.BOTH, expand=True)

    def _revoke(self):
        serial = self._serial.get().strip()
        vid    = self._vid.get().strip()
        reason = self._reason.get()

        if not serial or not vid:
            messagebox.showwarning("Missing Fields",
                                   "Enter both Serial Number and Vehicle ID.")
            return

        confirmed = messagebox.askyesno(
            "Confirm Revocation",
            f"Permanently revoke certificate?\n\n"
            f"  Serial  : {serial[:16]}…\n"
            f"  Vehicle : {vid}\n"
            f"  Reason  : {reason}\n\n"
            f"This cannot be undone.",
            icon="warning"
        )
        if not confirmed:
            return

        ok, msg = self._ca.revoke_certificate(serial, vid, reason)
        colour  = T.SUCCESS if ok else T.DANGER
        self._result.set(
            f"{'✔' if ok else '✘'}  {msg}", colour
        )
        self._set_status(msg)
        self._reload_table()

    def _reload_table(self):
        rows = database.fetch_all_revoked()
        self._table.load([
            (r["serial_number"][:12], r["vehicle_id"],
             r["revocation_reason"], r["revoked_at"][:19])
            for r in rows
        ])

    def on_show(self):
        self._reload_table()
