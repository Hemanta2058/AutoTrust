"""
config.py — AutoTrust Global Configuration
==========================================
Single source of truth for all paths, constants, and PKI parameters.
Every module imports from here — change once, propagates everywhere.

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import os

# ── Directory layout ────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
CERTIFICATES_DIR = os.path.join(BASE_DIR, "certificates")
KEYS_DIR         = os.path.join(BASE_DIR, "keys")
MESSAGES_DIR     = os.path.join(BASE_DIR, "messages")
DATABASE_DIR     = os.path.join(BASE_DIR, "database")
DATABASE_PATH    = os.path.join(DATABASE_DIR, "autotrust.db")

# ── Certificate Authority identity ──────────────────────────────────────────
CA_COMMON_NAME  = "AutoTrust Root CA"
CA_ORGANISATION = "AutoTrust V2V PKI Laboratory"
CA_COUNTRY      = "NP"
CA_CERT_FILE    = os.path.join(CERTIFICATES_DIR, "ca_cert.pem")
CA_KEY_FILE     = os.path.join(KEYS_DIR,         "ca_private.pem")

# ── Cryptographic parameters ────────────────────────────────────────────────
RSA_KEY_SIZE           = 2048
CERT_VALIDITY_DAYS     = 365
CA_VALIDITY_DAYS       = 3650
PKCS12_ITERATION_COUNT = 100_000

# ── Application metadata ────────────────────────────────────────────────────
APP_TITLE   = "AutoTrust"
APP_VERSION = "2.0.0"
APP_TAGLINE = "PKI-Based Vehicle-to-Vehicle Secure Communication"


def ensure_directories() -> None:
    """Create all required subdirectories on first run."""
    for d in (CERTIFICATES_DIR, KEYS_DIR, MESSAGES_DIR, DATABASE_DIR):
        os.makedirs(d, exist_ok=True)
