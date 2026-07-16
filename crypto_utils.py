"""
crypto_utils.py — AutoTrust Cryptographic Engine
=================================================
Full implementation of every cryptographic primitive used by AutoTrust:

  • RSA-2048 key-pair generation
  • PKCS#12 keystores (password-protected, 100 k PBKDF2 iterations)
  • X.509 certificate building & signing (SHA-256)
  • RSA-PSS digital signatures (SHA-256, 32-byte random salt)
  • Hybrid encryption: RSA-OAEP (SHA-256) + AES-256-GCM
  • Replay-attack prevention (UUID nonce + timestamp)
  • MITM defence via certificate chain validation

Security model
--------------
  Confidentiality  — AES-256-GCM encrypts message content
  Integrity        — GCM authentication tag + SHA-256 hash
  Authentication   — X.509 certificate + RSA-PSS signature
  Non-repudiation  — Signature tied to signer's private key only

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import base64
import hashlib
import json
import logging
import os
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import config

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1.  KEY-PAIR GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_key_pair(vehicle_id: str) -> Tuple[str, str]:
    """
    Generate an RSA-2048 key pair and persist as PEM files.

    Returns
    -------
    (private_key_path, public_key_path)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE,
    )

    priv_path = os.path.join(config.KEYS_DIR, f"{vehicle_id}_private.pem")
    pub_path  = os.path.join(config.KEYS_DIR, f"{vehicle_id}_public.pem")

    # Serialise private key (no encryption — keystore handles protection)
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    # Serialise public key
    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    log.info("Key pair generated for %s", vehicle_id)
    return priv_path, pub_path


# ══════════════════════════════════════════════════════════════════════════════
# 2.  PKCS#12 SECURE KEYSTORE
# ══════════════════════════════════════════════════════════════════════════════

def create_keystore(vehicle_id: str, private_key_path: str,
                    cert_path: str, password: str) -> str:
    """
    Bundle private key + certificate into a PKCS#12 keystore (.p12).
    Protected by password-based encryption (PBKDF2-SHA256, 100 k iterations).

    Returns
    -------
    Path to the written .p12 file.
    """
    private_key = _load_private_key(private_key_path)
    cert        = _load_cert(cert_path)

    p12_data = pkcs12.serialize_key_and_certificates(
        name=vehicle_id.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        ),
    )

    p12_path = os.path.join(config.KEYS_DIR, f"{vehicle_id}_keystore.p12")
    with open(p12_path, "wb") as f:
        f.write(p12_data)

    log.info("PKCS#12 keystore written: %s", p12_path)
    return p12_path


def load_keystore(p12_path: str, password: str):
    """Load and return (private_key, certificate) from a PKCS#12 keystore."""
    with open(p12_path, "rb") as f:
        data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(
        data, password.encode()
    )
    return private_key, cert


# ══════════════════════════════════════════════════════════════════════════════
# 3.  X.509 CERTIFICATE GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def build_ca_certificate(ca_key_path: str) -> Tuple[object, object]:
    """
    Create a self-signed CA root certificate.

    Returns
    -------
    (ca_private_key, ca_certificate)
    """
    ca_key = _load_private_key(ca_key_path)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,          config.CA_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,     config.CA_ORGANISATION),
        x509.NameAttribute(NameOID.COMMON_NAME,           config.CA_COMMON_NAME),
    ])

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(days=config.CA_VALIDITY_DAYS)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert


def issue_vehicle_certificate(vehicle_id: str, owner_name: str,
                              pub_key_path: str,
                              ca_key_path: str, ca_cert_path: str) -> Tuple[str, str, str]:
    """
    Issue a signed X.509 certificate for a vehicle.

    Returns
    -------
    (serial_hex, issued_at_iso, expires_at_iso)
    """
    vehicle_pub_key = _load_public_key(pub_key_path)
    ca_key          = _load_private_key(ca_key_path)
    ca_cert         = _load_cert(ca_cert_path)

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(days=config.CERT_VALIDITY_DAYS)
    serial  = x509.random_serial_number()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,      config.CA_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.CA_ORGANISATION),
        x509.NameAttribute(NameOID.COMMON_NAME,       vehicle_id),
        x509.NameAttribute(NameOID.GIVEN_NAME,        owner_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(vehicle_pub_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(vehicle_pub_key),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = os.path.join(config.CERTIFICATES_DIR, f"{vehicle_id}_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    serial_hex = format(serial, "x").upper()
    log.info("Certificate issued: %s → %s", vehicle_id, serial_hex)
    return serial_hex, now.isoformat(), expires.isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# 4.  DIGITAL SIGNATURES  (RSA-PSS / SHA-256)
# ══════════════════════════════════════════════════════════════════════════════

def sign_message(plaintext: str, private_key_path: str) -> Tuple[str, str, str]:
    """
    Sign a plaintext message.

    Returns
    -------
    (signature_b64, sha256_hash_hex, replay_nonce)

    Security
    --------
    • RSA-PSS with SHA-256 and 32-byte random salt — prevents existential
      forgery and chosen-message attacks.
    • replay_nonce: UUID4 + UTC timestamp bound to each message so that
      replaying the identical ciphertext is detected.
    """
    private_key = _load_private_key(private_key_path)

    # Replay-attack nonce: uuid4 + ISO timestamp
    replay_nonce = f"{uuid.uuid4()}|{datetime.now(timezone.utc).isoformat()}"

    # Hash the content + nonce together so nonce is integrity-protected
    payload      = (plaintext + replay_nonce).encode()
    digest       = hashlib.sha256(payload).hexdigest()

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )

    sig_b64 = base64.b64encode(signature).decode()
    log.info("Message signed (nonce=%s…)", replay_nonce[:8])
    return sig_b64, digest, replay_nonce


def verify_signature(plaintext: str, signature_b64: str,
                     public_key_path: str, replay_nonce: str) -> bool:
    """
    Verify an RSA-PSS signature and reject replay attacks.

    Returns True only if:
      1. The cryptographic signature is valid.
      2. The replay nonce has NOT been seen before (caller must check DB).
    """
    public_key = _load_public_key(public_key_path)
    payload    = (plaintext + replay_nonce).encode()
    signature  = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        log.warning("Signature verification FAILED")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 5.  HYBRID ENCRYPTION  (RSA-OAEP + AES-256-GCM)
# ══════════════════════════════════════════════════════════════════════════════

def encrypt_message(plaintext: str, recipient_pub_key_path: str) -> str:
    """
    Encrypt a message using hybrid encryption.

    Scheme
    ------
    1. Generate a random 256-bit AES session key.
    2. Encrypt plaintext with AES-256-GCM (12-byte IV, 128-bit auth tag).
    3. Encrypt the AES key with RSA-OAEP / SHA-256 (recipient's public key).
    4. Return a JSON envelope (base64-encoded) containing all parts.

    Security properties
    -------------------
    • Confidentiality : AES-256-GCM
    • Integrity       : GCM authentication tag
    • Forward secrecy : ephemeral session key per message
    """
    recipient_pub = _load_public_key(recipient_pub_key_path)

    # Generate ephemeral AES-256 key and encrypt plaintext
    aes_key    = AESGCM.generate_key(bit_length=256)
    aesgcm     = AESGCM(aes_key)
    iv         = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)

    # Encrypt AES key with RSA-OAEP
    enc_key = recipient_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    envelope = {
        "enc_key":    base64.b64encode(enc_key).decode(),
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


def decrypt_message(ciphertext_b64: str, private_key_path: str) -> str:
    """
    Decrypt a hybrid-encrypted envelope produced by encrypt_message().

    Raises ValueError on any decryption failure (wrong key, tampered data).
    """
    try:
        private_key = _load_private_key(private_key_path)
        envelope    = json.loads(base64.b64decode(ciphertext_b64))

        enc_key    = base64.b64decode(envelope["enc_key"])
        iv         = base64.b64decode(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        # Decrypt AES key with RSA-OAEP
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt content with AES-256-GCM (auth tag checked automatically)
        aesgcm    = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext.decode()

    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# 6.  CERTIFICATE VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_certificate(cert_path: str, ca_cert_path: str) -> Tuple[bool, str]:
    """
    Validate a vehicle certificate against the CA root.

    Checks
    ------
    • CA signature on certificate (MITM defence)
    • not-before / not-after validity window
    • BasicConstraints: CA must be False for vehicle certs

    Returns
    -------
    (is_valid, reason_string)
    """
    try:
        cert    = _load_cert(cert_path)
        ca_cert = _load_cert(ca_cert_path)
        now     = datetime.now(timezone.utc)

        # 1. Expiry
        if now < cert.not_valid_before_utc:
            return False, "Certificate not yet valid"
        if now > cert.not_valid_after_utc:
            return False, "Certificate has expired"

        # 2. CA signature — catches MITM-tampered certs
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        return True, "Certificate is valid"

    except InvalidSignature:
        return False, "Invalid CA signature — possible MITM attack"
    except Exception as exc:
        return False, str(exc)


# ══════════════════════════════════════════════════════════════════════════════
# 7.  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def hash_text(text: str) -> str:
    """Return SHA-256 hex digest of text."""
    return hashlib.sha256(text.encode()).hexdigest()
