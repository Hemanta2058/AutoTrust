"""Verify Message page — signature verification + replay detection."""

import tkinter as tk
from tkinter import messagebox
from gui import theme as T
from gui.widgets import Divider, LabelledEntry, PrimaryButton, ResultPanel
import database
import crypto_utils
import os, config


class VerifyPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Verify Signature",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr,
                 text="Verify RSA-PSS signature and detect replay attacks",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, T.PAD_XL))

        tk.Label(left, text="Load from DB", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._msg_id = LabelledEntry(left, "Message ID",
                                      placeholder="Paste message_id from Audit Log or Sign result")
        self._msg_id.pack(fill=tk.X, pady=T.PAD_SM)

        PrimaryButton(left, "Load & Verify from DB", icon="📂",
                      command=self._verify_from_db).pack(
            anchor="w", pady=(T.PAD_SM, T.PAD_LG))

        # Info box
        tk.Label(left,
                 text="Tip: Copy Message ID from the Sign page result\n"
                      "or from the Audit Log page.",
                 font=T.FONT_SMALL, fg=T.TEXT_MUTED,
                 bg=T.BG_BASE, justify=tk.LEFT).pack(anchor="w", pady=(0, T.PAD_LG))

        Divider(left, colour=T.BORDER).pack(fill=tk.X, pady=T.PAD_MD)

        tk.Label(left, text="Manual Verify", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))

        self._sender_id = LabelledEntry(left, "Sender Vehicle ID",
                                         placeholder="e.g. VH-A1B2C3D4")
        self._sender_id.pack(fill=tk.X, pady=T.PAD_SM)

        self._sig = LabelledEntry(left, "Signature (base64)",
                                   placeholder="Paste signature here")
        self._sig.pack(fill=tk.X, pady=T.PAD_SM)

        self._nonce = LabelledEntry(left, "Replay Nonce",
                                     placeholder="Nonce from signed message")
        self._nonce.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(left, text="Plaintext", font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._plain = tk.Text(left, height=4, width=38,
                               bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                               font=T.FONT_BODY, relief=tk.FLAT,
                               insertbackground=T.ACCENT,
                               highlightbackground=T.BORDER,
                               highlightthickness=1)
        self._plain.pack(fill=tk.X, pady=(2, T.PAD_SM))

        PrimaryButton(left, "Verify Manually", icon="🔍",
                      command=self._verify_manual).pack(
            anchor="w", pady=T.PAD_MD)

        # Right: result
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(right, text="Verification Result", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._result = ResultPanel(right)
        self._result.pack(fill=tk.BOTH, expand=True)

    def _verify_from_db(self):
        mid = self._msg_id.get().strip()
        if not mid:
            messagebox.showwarning("Missing", "Enter a Message ID.")
            return

        rows = database.fetch_all_messages()
        row  = next((r for r in rows if r["message_id"] == mid), None)
        if row is None:
            self._result.set(f"✘  Message ID not found in database.\n\n"
                              f"  Go to Audit Log to find valid message IDs.",
                              T.DANGER)
            return

        sender_id = row["sender_id"]
        pub_path  = os.path.join(config.KEYS_DIR, f"{sender_id}_public.pem")
        if not os.path.isfile(pub_path):
            self._result.set(f"✘  Public key for {sender_id} not found.", T.DANGER)
            return

        # Already verified — demonstrate replay attack
        if row["is_verified"]:
            self._result.set(
                f"⚠  REPLAY ATTACK detected!\n\n"
                f"  This message was already verified once.\n"
                f"  The nonce cannot be reused — request blocked.\n\n"
                f"  Message ID : {mid[:32]}…\n"
                f"  Sender     : {sender_id}\n\n"
                f"  This is anti-replay protection working correctly.",
                T.WARNING
            )
            self._set_status("Replay attack detected and blocked.")
            return

        # First time verify — perform cryptographic check
        ok = crypto_utils.verify_signature(
            row["plaintext"], row["signature"],
            pub_path, row["replay_token"]
        )
        if ok:
            database.mark_message_verified(mid)
            text = (
                f"✔  Signature VALID\n\n"
                f"  Message ID : {mid}\n"
                f"  Sender     : {sender_id}\n"
                f"  Plaintext  : {row['plaintext']}\n"
                f"  SHA-256    : {row['message_hash'][:32]}…\n"
                f"  Nonce      : {row['replay_token'][:36]}…\n\n"
                f"  Message is authentic and unmodified.\n"
                f"  Tip: Verify again to see replay attack detection."
            )
            self._result.set(text, T.SUCCESS)
            self._set_status("Signature verified successfully.")
        else:
            self._result.set("✘  Signature INVALID — message may be tampered.",
                              T.DANGER)
            self._set_status("Verification failed.")

    def _verify_manual(self):
        sender = self._sender_id.get().strip()
        sig    = self._sig.get().strip()
        nonce  = self._nonce.get().strip()
        plain  = self._plain.get("1.0", tk.END).strip()

        if not all([sender, sig, nonce, plain]):
            messagebox.showwarning("Missing Fields", "Fill in all fields.")
            return

        pub_path = os.path.join(config.KEYS_DIR, f"{sender}_public.pem")
        if not os.path.isfile(pub_path):
            self._result.set(f"✘  Public key for {sender} not found.", T.DANGER)
            return

        if database.replay_token_exists(nonce):
            self._result.set("⚠  REPLAY ATTACK — nonce already in database.",
                              T.WARNING)
            return

        ok = crypto_utils.verify_signature(plain, sig, pub_path, nonce)
        colour = T.SUCCESS if ok else T.DANGER
        self._result.set(
            f"{'✔  Signature VALID' if ok else '✘  Signature INVALID'}\n\n"
            f"  Sender : {sender}",
            colour
        )
        self._set_status("Verification complete.")
