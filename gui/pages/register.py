"""Register Vehicle page — generates RSA key pair and records vehicle."""

import tkinter as tk
from tkinter import messagebox
from gui import theme as T
from gui.widgets import (Card, Divider, LabelledEntry, LabelledCombo,
                          PrimaryButton, ResultPanel)
from vehicle import Vehicle


VEHICLE_TYPES = ["Car", "Truck", "Bus", "Motorcycle", "Emergency Vehicle",
                 "Autonomous Vehicle", "SUV", "Van"]


class RegisterPage(tk.Frame):
    def __init__(self, parent, ca, set_status):
        super().__init__(parent, bg=T.BG_BASE)
        self._ca         = ca
        self._set_status = set_status
        self._build()

    def _build(self):
        # Page header
        hdr = tk.Frame(self, bg=T.BG_BASE, pady=T.PAD_LG, padx=T.PAD_XL)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Register Vehicle",
                 font=T.FONT_TITLE, fg=T.TEXT_PRIMARY,
                 bg=T.BG_BASE).pack(anchor="w")
        tk.Label(hdr, text="Generate an RSA-2048 key pair and enrol a new V2V participant",
                 font=T.FONT_SMALL, fg=T.TEXT_SECONDARY,
                 bg=T.BG_BASE).pack(anchor="w")
        Divider(self).pack(fill=tk.X, padx=T.PAD_XL)

        body = tk.Frame(self, bg=T.BG_BASE, padx=T.PAD_XL, pady=T.PAD_LG)
        body.pack(fill=tk.BOTH, expand=True)

        # Left: form
        left = tk.Frame(body, bg=T.BG_BASE)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, T.PAD_XL))

        self._name = LabelledEntry(left, "Owner Name",
                                   placeholder="e.g. Alice Johnson")
        self._name.pack(fill=tk.X, pady=T.PAD_SM)

        self._type = LabelledCombo(left, "Vehicle Type", VEHICLE_TYPES)
        self._type.pack(fill=tk.X, pady=T.PAD_SM)

        self._vid_entry = LabelledEntry(left, "Custom Vehicle ID (optional)",
                                        placeholder="Leave blank to auto-generate")
        self._vid_entry.pack(fill=tk.X, pady=T.PAD_SM)

        tk.Label(left, text="A unique RSA-2048 key pair will be generated\n"
                             "and stored securely in the keys/ directory.",
                 font=T.FONT_SMALL, fg=T.TEXT_MUTED,
                 bg=T.BG_BASE, justify=tk.LEFT).pack(anchor="w", pady=T.PAD_SM)

        PrimaryButton(left, "Register & Generate Keys",
                      icon="🚗", command=self._register).pack(
            anchor="w", pady=T.PAD_MD)

        # Right: result
        right = tk.Frame(body, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="Registration Result",
                 font=T.FONT_BODY_B, fg=T.TEXT_ACCENT,
                 bg=T.BG_BASE).pack(anchor="w", pady=(0, 4))
        self._result = ResultPanel(right)
        self._result.pack(fill=tk.BOTH, expand=True)

        # Info card
        info = Card(right, title="What happens?")
        info.pack(fill=tk.X, pady=T.PAD_MD)
        for line in [
            "① RSA-2048 private & public keys are generated",
            "② Keys saved to keys/<vehicle_id>_private.pem",
            "③ Vehicle record stored in SQLite database",
            "④ Next step: Issue a certificate for this vehicle",
        ]:
            tk.Label(info, text=line, font=T.FONT_SMALL,
                     fg=T.TEXT_SECONDARY, bg=T.BG_CARD,
                     justify=tk.LEFT).pack(anchor="w",
                                           padx=T.PAD_MD, pady=2)
        tk.Frame(info, bg=T.BG_CARD, height=8).pack()

    def _register(self):
        name = self._name.get().strip()
        if not name:
            messagebox.showwarning("Missing Field", "Please enter the owner name.")
            return

        vtype = self._type.get()
        custom_id = self._vid_entry.get().strip() or None

        self._set_status("Registering vehicle and generating RSA keys…")
        v = Vehicle(owner_name=name, vehicle_type=vtype, vehicle_id=custom_id)
        ok, msg = v.register()

        if ok:
            text = (
                f"✔  Registration Successful\n\n"
                f"  Vehicle ID   : {v.vehicle_id}\n"
                f"  Owner        : {v.owner_name}\n"
                f"  Type         : {v.vehicle_type}\n\n"
                f"  Private key  : keys/{v.vehicle_id}_private.pem\n"
                f"  Public key   : keys/{v.vehicle_id}_public.pem\n\n"
                f"  Next step: go to Certificate page to issue a certificate."
            )
            self._result.set(text, T.SUCCESS)
            self._set_status(f"Vehicle {v.vehicle_id} registered.")
        else:
            self._result.set(f"✘  {msg}", T.DANGER)
            self._set_status("Registration failed.")
