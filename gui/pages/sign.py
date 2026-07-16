"""Sign Message page — RSA-PSS digital signatures with replay protection."""

import tkinter as tk
from tkinter import messagebox
from gui import theme as T
from gui.widgets import (Divider, LabelledEntry, PrimaryButton, ResultPanel)
import database


class SignPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._last_sig   = {}
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Sign Message",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr,
                 text="RSA-PSS / SHA-256 signature with replay-attack nonce",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, T.PAD_XL))

        self._vid = LabelledEntry(left, "Sender Vehicle ID",
                                   placeholder="e.g. VH-A1B2C3D4")
        self._vid.pack(fill=tk.X, pady=T.PAD_SM)

        self._serial = LabelledEntry(left, "Certificate Serial",
                                      placeholder="Must be VALID (not revoked)")
        self._serial.pack(fill=tk.X, pady=T.PAD_SM)

        self._recipient = LabelledEntry(left, "Recipient Vehicle ID (optional)",
                                         placeholder="Leave blank for broadcast")
        self._recipient.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(left, text="Message", font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._msg = tk.Text(left, height=5, width=38,
                             bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                             font=T.FONT_BODY, relief=tk.FLAT,
                             insertbackground=T.ACCENT,
                             highlightbackground=T.BORDER,
                             highlightthickness=1)
        self._msg.pack(fill=tk.X, pady=(2, T.PAD_SM))

        PrimaryButton(left, "Sign Message", icon="✍️",
                      command=self._sign).pack(anchor="w", pady=T.PAD_MD)

        # Right: output
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Signature Output", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._result = ResultPanel(right)
        self._result.pack(fill=tk.BOTH, expand=True)

        # Security info
        tk.Frame(right, bg=T.BG_BASE, height=T.PAD_SM).pack()
        for line in [
            "🔐  Algorithm : RSA-PSS with SHA-256",
            "🔐  Salt      : 32 bytes (random per message)",
            "🔐  Nonce     : UUID4 + timestamp (anti-replay)",
            "🔐  Non-repudiation: only the private key can sign",
        ]:
            tk.Label(right, text=line, font=T.FONT_SMALL,
                     fg=T.TEXT_MUTED, bg=T.BG_BASE,
                     justify=tk.LEFT).pack(anchor="w")

    def _sign(self):
        from vehicle import Vehicle
        vid    = self._vid.get().strip()
        serial = self._serial.get().strip()
        recip  = self._recipient.get().strip()
        msg    = self._msg.get("1.0", tk.END).strip()

        if not all([vid, serial, msg]):
            messagebox.showwarning("Missing Fields",
                                   "Fill in Vehicle ID, Serial, and Message.")
            return

        v = Vehicle.from_db(vid)
        if v is None:
            self._result.set(f"✘  Vehicle '{vid}' not found.", T.DANGER)
            return

        # Authenticate before signing
        auth_ok, auth_msg = v.authenticate(serial, self._ca)
        if not auth_ok:
            self._result.set(f"✘  Auth failed: {auth_msg}", T.DANGER)
            return

        self._set_status("Signing message…")
        ok, out_msg, detail = v.sign(msg, recip)

        if ok:
            self._last_sig = detail
            text = (
                f"✔  Message Signed Successfully\n\n"
                f"  Sender      : {vid}\n"
                f"  Recipient   : {recip or 'Broadcast'}\n"
                f"  Message ID  : {detail['message_id']}\n"
                f"  SHA-256     : {detail['hash'][:32]}…\n"
                f"  Signature   : {detail['signature']}\n"
                f"  Nonce       : {detail['nonce'][:36]}…\n\n"
                f"  Saved to signed_messages table."
            )
            self._result.set(text, T.SUCCESS)
            self._set_status("Message signed.")
        else:
            self._result.set(f"✘  {out_msg}", T.DANGER)
            self._set_status("Signing failed.")
