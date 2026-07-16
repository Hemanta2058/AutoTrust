"""Certificate page — issue X.509 certs and authenticate vehicles."""

import tkinter as tk
from tkinter import messagebox
from gui import theme as T
from gui.widgets import (Card, Divider, LabelledEntry,
                          PrimaryButton, ResultPanel, DataTable, StatusBadge)
import database


class CertificatePage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Certificate Management",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr, text="Issue X.509 certificates signed by the AutoTrust Root CA",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        # ── Left: Issue form ───────────────────────────────────────────────
        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, T.PAD_XL))

        tk.Label(left, text="Issue Certificate", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 8))

        self._vid = LabelledEntry(left, "Vehicle ID",
                                   placeholder="e.g. VH-A1B2C3D4")
        self._vid.pack(fill=tk.X, pady=T.PAD_SM)

        self._pw = LabelledEntry(left, "Keystore Password",
                                  placeholder="Password for PKCS#12 keystore",
                                  show="●")
        self._pw.pack(fill=tk.X, pady=T.PAD_SM)

        PrimaryButton(left, "Issue Certificate",
                      icon="📜", command=self._issue).pack(
            anchor="w", pady=T.PAD_MD)

        Divider(left, colour=T.BORDER).pack(fill=tk.X, pady=T.PAD_MD)

        tk.Label(left, text="Authenticate Vehicle", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 8))

        self._auth_vid = LabelledEntry(left, "Vehicle ID",
                                        placeholder="Vehicle to authenticate")
        self._auth_vid.pack(fill=tk.X, pady=T.PAD_SM)

        self._auth_serial = LabelledEntry(left, "Certificate Serial (full)",
                                           placeholder="Paste full serial from table above",
                                           width=50)
        self._auth_serial.pack(fill=tk.X, pady=T.PAD_SM)

        PrimaryButton(left, "Authenticate",
                      icon="🔑", command=self._authenticate).pack(
            anchor="w", pady=T.PAD_MD)

        # ── Right: result + table ──────────────────────────────────────────
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Result", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._result = ResultPanel(right)
        self._result.pack(fill=tk.X, pady=(0, T.PAD_MD))

        tk.Label(right, text="All Certificates", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._table = DataTable(
            right,
            columns=["Full Serial Number", "Vehicle", "Issued By", "Status", "Expires"],
            col_widths=[42, 14, 18, 8, 12]
        )
        self._table.pack(fill=tk.BOTH, expand=True)

    def _issue(self):
        vid = self._vid.get().strip()
        pw  = self._pw.get().strip() or "autotrust"
        if not vid:
            messagebox.showwarning("Missing Field", "Enter a Vehicle ID.")
            return

        row = database.fetch_vehicle(vid)
        if row is None:
            self._result.set(f"✘  Vehicle '{vid}' not found. Register it first.",
                              T.DANGER)
            return

        self._set_status("Issuing X.509 certificate…")
        ok, msg = self._ca.issue_certificate(
            vehicle_id   = vid,
            owner_name   = row["owner_name"],
            pub_key_path = row["public_key_path"],
            password     = pw,
        )

        if ok:
            certs = database.fetch_certificates_for_vehicle(vid)
            serial = certs[0]["serial_number"] if certs else "—"
            text = (
                f"✔  Certificate Issued\n\n"
                f"  Vehicle   : {vid}\n"
                f"  Owner     : {row['owner_name']}\n"
                f"  Serial    : {serial}\n"
                f"  Signed by : {self._ca.name}\n"
                f"  Algorithm : RSA-2048 / SHA-256\n"
                f"  Keystore  : PKCS#12 (password-protected)\n"
                f"  Validity  : 365 days"
            )
            self._result.set(text, T.SUCCESS)
            self._set_status(f"Certificate issued for {vid}.")
        else:
            self._result.set(f"✘  {msg}", T.DANGER)
            self._set_status("Certificate issuance failed.")

        self._reload_table()

    def _authenticate(self):
        from vehicle import Vehicle
        vid    = self._auth_vid.get().strip()
        serial = self._auth_serial.get().strip()
        if not vid or not serial:
            messagebox.showwarning("Missing Fields",
                                   "Enter both Vehicle ID and Serial.")
            return

        v = Vehicle.from_db(vid)
        if v is None:
            self._result.set(f"✘  Vehicle '{vid}' not found.", T.DANGER)
            return

        ok, msg = v.authenticate(serial, self._ca)
        colour  = T.SUCCESS if ok else T.DANGER
        prefix  = "✔" if ok else "✘"
        self._result.set(f"{prefix}  {msg}", colour)
        self._set_status(msg)

    def _reload_table(self):
        rows = database.fetch_all_certificates()
        self._table.load([
            (r["serial_number"], r["vehicle_id"],
             r["issued_by"][:16], r["status"], r["expires_at"][:10])
            for r in rows
        ])

    def on_show(self):
        self._reload_table()
