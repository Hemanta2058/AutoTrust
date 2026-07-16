"""Encrypt / Decrypt page — RSA-OAEP + AES-256-GCM hybrid encryption."""

import tkinter as tk
from tkinter import messagebox
import os
import config
from gui import theme as T
from gui.widgets import Divider, LabelledEntry, PrimaryButton, SecondaryButton
import crypto_utils


class EncryptPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Encrypt & Decrypt Messages",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr,
                 text="Hybrid encryption: RSA-OAEP (key wrap) + AES-256-GCM (content)",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        # Left: encrypt panel
        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                  padx=(0, T.PAD_MD))

        tk.Label(left, text="Encrypt", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))

        self._recip = LabelledEntry(left, "Recipient Vehicle ID",
                                     placeholder="e.g. VH-A1B2C3D4")
        self._recip.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(left, text="Plaintext Message", font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._plain = tk.Text(left, height=5,
                               bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                               font=T.FONT_BODY, relief=tk.FLAT,
                               insertbackground=T.ACCENT,
                               highlightbackground=T.BORDER,
                               highlightthickness=1)
        self._plain.pack(fill=tk.X, pady=(2, T.PAD_SM))

        btn_row = tk.Frame(left, bg=T.BG_BASE)
        btn_row.pack(anchor="w", pady=T.PAD_SM)
        PrimaryButton(btn_row, "Encrypt", icon="🔒",
                      command=self._encrypt).pack(side=tk.LEFT, padx=(0, 8))
        SecondaryButton(btn_row, "Clear",
                        command=self._clear_enc).pack(side=tk.LEFT)

        tk.Label(left, text="Ciphertext (base64 envelope)",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w", pady=(T.PAD_MD, 0))
        self._enc_out = tk.Text(left, height=7,
                                 bg=T.BG_INPUT, fg=T.WARNING,
                                 font=T.FONT_MONO, relief=tk.FLAT,
                                 highlightbackground=T.BORDER,
                                 highlightthickness=1, wrap=tk.WORD)
        self._enc_out.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

        # Right: decrypt panel
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Decrypt", font=T.FONT_BODY_B,
                 fg=T.TEXT_ACCENT, bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))

        self._dec_vid = LabelledEntry(right, "Recipient Vehicle ID",
                                       placeholder="Your vehicle ID")
        self._dec_vid.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(right, text="Ciphertext (paste here)", font=T.FONT_SMALL,
                 fg=T.TEXT_SECONDARY, bg=T.BG_BASE).pack(anchor="w")
        self._ct_in = tk.Text(right, height=7,
                               bg=T.BG_INPUT, fg=T.WARNING,
                               font=T.FONT_MONO, relief=tk.FLAT,
                               insertbackground=T.ACCENT,
                               highlightbackground=T.BORDER,
                               highlightthickness=1, wrap=tk.WORD)
        self._ct_in.pack(fill=tk.X, pady=(2, T.PAD_SM))

        btn_row2 = tk.Frame(right, bg=T.BG_BASE)
        btn_row2.pack(anchor="w", pady=T.PAD_SM)
        PrimaryButton(btn_row2, "Decrypt", icon="🔓",
                      command=self._decrypt).pack(side=tk.LEFT, padx=(0, 8))
        SecondaryButton(btn_row2, "Paste from Encrypt",
                        command=self._paste_from_enc).pack(side=tk.LEFT)

        tk.Label(right, text="Decrypted Plaintext",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w", pady=(T.PAD_MD, 0))
        self._dec_out = tk.Text(right, height=7,
                                 bg=T.BG_INPUT, fg=T.SUCCESS,
                                 font=T.FONT_BODY, relief=tk.FLAT,
                                 highlightbackground=T.BORDER,
                                 highlightthickness=1, wrap=tk.WORD)
        self._dec_out.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

    def _encrypt(self):
        recip = self._recip.get().strip()
        plain = self._plain.get("1.0", tk.END).strip()
        if not recip or not plain:
            messagebox.showwarning("Missing Fields",
                                   "Enter recipient Vehicle ID and message.")
            return

        pub_path = os.path.join(config.KEYS_DIR, f"{recip}_public.pem")
        if not os.path.isfile(pub_path):
            self._write_enc(f"✘  Public key for '{recip}' not found.\n"
                             f"Register and issue a certificate first.", err=True)
            return

        try:
            self._set_status("Encrypting with AES-256-GCM + RSA-OAEP…")
            ct = crypto_utils.encrypt_message(plain, pub_path)
            self._write_enc(ct)
            self._set_status("Message encrypted.")
        except Exception as exc:
            self._write_enc(f"✘  {exc}", err=True)

    def _decrypt(self):
        vid = self._dec_vid.get().strip()
        ct  = self._ct_in.get("1.0", tk.END).strip()
        if not vid or not ct:
            messagebox.showwarning("Missing Fields",
                                   "Enter your Vehicle ID and the ciphertext.")
            return

        priv_path = os.path.join(config.KEYS_DIR, f"{vid}_private.pem")
        if not os.path.isfile(priv_path):
            self._write_dec(f"✘  Private key for '{vid}' not found.", err=True)
            return

        try:
            self._set_status("Decrypting…")
            plain = crypto_utils.decrypt_message(ct, priv_path)
            self._write_dec(plain)
            self._set_status("Message decrypted successfully.")
        except ValueError as exc:
            self._write_dec(f"✘  {exc}", err=True)

    def _write_enc(self, text: str, err: bool = False):
        self._enc_out.config(state=tk.NORMAL,
                              fg=T.DANGER if err else T.WARNING)
        self._enc_out.delete("1.0", tk.END)
        self._enc_out.insert(tk.END, text)
        self._enc_out.config(state=tk.DISABLED)

    def _write_dec(self, text: str, err: bool = False):
        self._dec_out.config(state=tk.NORMAL,
                              fg=T.DANGER if err else T.SUCCESS)
        self._dec_out.delete("1.0", tk.END)
        self._dec_out.insert(tk.END, text)
        self._dec_out.config(state=tk.DISABLED)

    def _paste_from_enc(self):
        ct = self._enc_out.get("1.0", tk.END).strip()
        self._ct_in.delete("1.0", tk.END)
        self._ct_in.insert(tk.END, ct)

    def _clear_enc(self):
        self._plain.delete("1.0", tk.END)
        self._enc_out.config(state=tk.NORMAL)
        self._enc_out.delete("1.0", tk.END)
        self._enc_out.config(state=tk.DISABLED)
