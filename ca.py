"""
ca.py — AutoTrust Certificate Authority
=======================================
Manages the root CA lifecycle: bootstrap, certificate issuance,
and revocation.  Delegates all cryptographic operations to crypto_utils.

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

import config
import crypto_utils
import database
from cryptography.hazmat.primitives import serialization

log = logging.getLogger(__name__)


class CertificateAuthority:
    """Singleton-style CA — one instance per application session."""

    def __init__(self) -> None:
        self.name        = config.CA_COMMON_NAME
        self.cert_path   = config.CA_CERT_FILE
        self.key_path    = config.CA_KEY_FILE
        self.initialised = False

    # ── Bootstrap ────────────────────────────────────────────────────────────

    def initialise(self) -> Tuple[bool, str]:
        """
        Generate CA key + self-signed certificate if they don't exist yet.

        Returns (success: bool, message: str)
        """
        if os.path.isfile(self.cert_path) and os.path.isfile(self.key_path):
            self.initialised = True
            log.info("CA already exists — loaded from disk.")
            return True, "CA loaded from existing files."

        try:
            # generate_key_pair("ca") writes ca_private.pem and ca_public.pem
            # The private key lands at KEYS_DIR/ca_private.pem which IS
            # config.CA_KEY_FILE, so no rename needed for the private key.
            crypto_utils.generate_key_pair("ca")

            # Build self-signed certificate
            _, ca_cert = crypto_utils.build_ca_certificate(self.key_path)

            with open(self.cert_path, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

            self.initialised = True
            log.info("CA initialised: %s", self.name)
            return True, f"CA '{self.name}' created successfully."

        except Exception as exc:
            log.error("CA initialisation failed: %s", exc)
            return False, f"CA initialisation failed: {exc}"

    # ── Certificate issuance ─────────────────────────────────────────────────

    def issue_certificate(self, vehicle_id: str, owner_name: str,
                          pub_key_path: str,
                          password: str = "autotrust") -> Tuple[bool, str]:
        """
        Issue a signed X.509 certificate and create a PKCS#12 keystore.

        Returns (success: bool, message: str)
        """
        if not self.initialised:
            return False, "CA not initialised."

        try:
            priv_path = os.path.join(config.KEYS_DIR, f"{vehicle_id}_private.pem")
            cert_path = os.path.join(config.CERTIFICATES_DIR, f"{vehicle_id}_cert.pem")

            serial, issued_at, expires_at = crypto_utils.issue_vehicle_certificate(
                vehicle_id  = vehicle_id,
                owner_name  = owner_name,
                pub_key_path= pub_key_path,
                ca_key_path = self.key_path,
                ca_cert_path= self.cert_path,
            )

            # Create PKCS#12 keystore
            ks_path = crypto_utils.create_keystore(
                vehicle_id, priv_path, cert_path, password
            )

            # Persist to database
            database.insert_certificate(
                serial     = serial,
                vehicle_id = vehicle_id,
                issued_by  = self.name,
                issued_at  = issued_at,
                expires_at = expires_at,
                cert_path  = cert_path,
            )
            database.update_vehicle_keys(vehicle_id, pub_key_path, ks_path)

            msg = f"Certificate issued. Serial: {serial[:12]}…"
            log.info(msg)
            return True, msg

        except Exception as exc:
            log.error("Issue certificate failed: %s", exc)
            return False, f"Failed to issue certificate: {exc}"

    # ── Revocation ───────────────────────────────────────────────────────────

    def revoke_certificate(self, serial: str, vehicle_id: str,
                           reason: str = "Unspecified") -> Tuple[bool, str]:
        """
        Revoke a certificate and add it to the CRL.

        Returns (success: bool, message: str)
        """
        if database.is_revoked(serial):
            return False, "Certificate is already revoked."

        row = database.fetch_certificate(serial)
        if row is None:
            return False, "Certificate not found in database."

        try:
            database.insert_revocation(serial, vehicle_id, reason)
            msg = f"Certificate {serial[:12]}… revoked. Reason: {reason}"
            log.info(msg)
            return True, msg
        except Exception as exc:
            log.error("Revocation failed: %s", exc)
            return False, f"Revocation failed: {exc}"

    # ── Validation ───────────────────────────────────────────────────────────

    def validate(self, vehicle_id: str) -> Tuple[bool, str]:
        """Check cert file validity (expiry + CA signature) for a vehicle."""
        cert_path = os.path.join(
            config.CERTIFICATES_DIR, f"{vehicle_id}_cert.pem"
        )
        if not os.path.isfile(cert_path):
            return False, "No certificate file found."
        return crypto_utils.validate_certificate(cert_path, self.cert_path)

    def __repr__(self) -> str:
        return f"CertificateAuthority({self.name!r}, init={self.initialised})"
