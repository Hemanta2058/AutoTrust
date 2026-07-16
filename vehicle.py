"""
vehicle.py — AutoTrust Vehicle Entity
======================================
Represents a V2V network participant.  Handles registration,
authentication, signing, and encryption at the vehicle level.

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import logging
import os
import uuid
from typing import Optional, Tuple

import config
import crypto_utils
import database

log = logging.getLogger(__name__)


class Vehicle:
    """A registered V2V participant with its own key pair and certificate."""

    def __init__(self, owner_name: str, vehicle_type: str,
                 vehicle_id: Optional[str] = None) -> None:
        self.vehicle_id      = vehicle_id or self._new_id()
        self.owner_name      = owner_name
        self.vehicle_type    = vehicle_type
        self.public_key_path = ""
        self.private_key_path= ""
        self.keystore_path   = ""
        self.authenticated   = False

    # ── Registration ─────────────────────────────────────────────────────────

    def register(self) -> Tuple[bool, str]:
        """
        Generate RSA key pair and persist vehicle record to database.

        Returns (success, message)
        """
        try:
            priv, pub = crypto_utils.generate_key_pair(self.vehicle_id)
            self.private_key_path = priv
            self.public_key_path  = pub

            database.insert_vehicle(
                vehicle_id      = self.vehicle_id,
                owner_name      = self.owner_name,
                vehicle_type    = self.vehicle_type,
                public_key_path = pub,
            )
            return True, f"Vehicle {self.vehicle_id} registered successfully."
        except Exception as exc:
            log.error("Vehicle registration failed: %s", exc)
            return False, f"Registration failed: {exc}"

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, serial_number: str, ca) -> Tuple[bool, str]:
        """
        Certificate-based authentication:
          1. Check certificate not revoked (CRL check)
          2. Validate CA signature on certificate
          3. Confirm certificate belongs to this vehicle

        Returns (success, message)
        """
        # CRL check
        if database.is_revoked(serial_number):
            self.authenticated = False
            return False, "Authentication FAILED — certificate is revoked."

        # Database record check
        row = database.fetch_certificate(serial_number)
        if row is None:
            return False, "Certificate not found."
        if row["vehicle_id"] != self.vehicle_id:
            return False, "Certificate does not belong to this vehicle."

        # Cryptographic validation
        valid, reason = ca.validate(self.vehicle_id)
        if valid:
            self.authenticated = True
            return True, f"Authenticated. {reason}"
        self.authenticated = False
        return False, f"Authentication FAILED — {reason}"

    # ── Signing ───────────────────────────────────────────────────────────────

    def sign(self, plaintext: str,
             recipient_id: str = "") -> Tuple[bool, str, dict]:
        """
        Sign a V2V message and record it in the database.

        Returns (success, message, detail_dict)
        """
        if not self.authenticated:
            return False, "Vehicle not authenticated.", {}
        if not os.path.isfile(self.private_key_path):
            return False, "Private key not found.", {}

        try:
            sig_b64, digest, nonce = crypto_utils.sign_message(
                plaintext, self.private_key_path
            )
            msg_id = uuid.uuid4().hex

            # Replay-attack check — nonce must be unique
            if database.replay_token_exists(nonce):
                return False, "Replay attack detected — duplicate nonce.", {}

            database.insert_message(
                message_id   = msg_id,
                sender_id    = self.vehicle_id,
                plaintext    = plaintext,
                message_hash = digest,
                signature    = sig_b64,
                recipient_id = recipient_id,
                replay_token = nonce,
            )
            detail = {
                "message_id": msg_id,
                "hash":       digest,
                "signature":  sig_b64[:40] + "…",
                "nonce":      nonce,
            }
            return True, "Message signed successfully.", detail
        except Exception as exc:
            log.error("Signing failed: %s", exc)
            return False, f"Signing failed: {exc}", {}

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify(self, plaintext: str, signature_b64: str,
               sender_pub_key_path: str,
               replay_nonce: str) -> Tuple[bool, str]:
        """
        Verify a received V2V message signature.

        Returns (success, message)
        """
        # Replay attack check
        if database.replay_token_exists(replay_nonce):
            return False, "REPLAY ATTACK detected — nonce already used."

        valid = crypto_utils.verify_signature(
            plaintext, signature_b64, sender_pub_key_path, replay_nonce
        )
        if valid:
            return True, "Signature VALID — message is authentic."
        return False, "Signature INVALID — message may be tampered."

    # ── Encrypt ───────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: str,
                recipient_pub_key_path: str) -> Tuple[bool, str]:
        """
        Encrypt a message for a recipient using hybrid encryption.

        Returns (success, ciphertext_or_error)
        """
        try:
            ct = crypto_utils.encrypt_message(plaintext, recipient_pub_key_path)
            return True, ct
        except Exception as exc:
            return False, f"Encryption failed: {exc}"

    # ── Decrypt ───────────────────────────────────────────────────────────────

    def decrypt(self, ciphertext_b64: str) -> Tuple[bool, str]:
        """
        Decrypt a hybrid-encrypted message addressed to this vehicle.

        Returns (success, plaintext_or_error)
        """
        if not os.path.isfile(self.private_key_path):
            return False, "Private key not found."
        try:
            pt = crypto_utils.decrypt_message(ciphertext_b64, self.private_key_path)
            return True, pt
        except ValueError as exc:
            return False, str(exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _new_id() -> str:
        return "VH-" + uuid.uuid4().hex[:8].upper()

    @classmethod
    def from_db(cls, vehicle_id: str) -> Optional["Vehicle"]:
        """Load a Vehicle from the database (keys must already exist on disk)."""
        row = database.fetch_vehicle(vehicle_id)
        if row is None:
            return None
        v = cls(row["owner_name"], row["vehicle_type"], row["vehicle_id"])
        v.public_key_path  = row["public_key_path"] or ""
        v.private_key_path = os.path.join(
            config.KEYS_DIR, f"{vehicle_id}_private.pem"
        )
        v.keystore_path = row["keystore_path"] or ""
        return v

    def __repr__(self) -> str:
        return (f"Vehicle(id={self.vehicle_id!r}, "
                f"owner={self.owner_name!r}, auth={self.authenticated})")
