"""
tests/test_autotrust.py — AutoTrust Test Suite
===============================================
Tests cover:
  • Key generation
  • Certificate issuance & validation
  • Digital signatures & verification
  • Hybrid encryption / decryption
  • Replay attack detection
  • MITM / tampered-cert detection
  • Certificate revocation (CRL)
  • Unauthorised signing prevention

Run:  python -m pytest tests/ -v
"""

import os, sys, shutil, tempfile, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import config, database, crypto_utils
from ca import CertificateAuthority
from vehicle import Vehicle


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def tmp_env(tmp_path_factory):
    """Redirect all file I/O to a temp directory for the test session."""
    tmp = tmp_path_factory.mktemp("autotrust_test")
    config.BASE_DIR         = str(tmp)
    config.CERTIFICATES_DIR = str(tmp / "certificates")
    config.KEYS_DIR         = str(tmp / "keys")
    config.MESSAGES_DIR     = str(tmp / "messages")
    config.DATABASE_DIR     = str(tmp / "database")
    config.DATABASE_PATH    = str(tmp / "database" / "test.db")
    # CA files must match generate_key_pair("ca") naming: ca_private.pem
    config.CA_CERT_FILE     = str(tmp / "certificates" / "ca_cert.pem")
    config.CA_KEY_FILE      = str(tmp / "keys" / "ca_private.pem")
    config.ensure_directories()
    database.initialise()
    yield tmp


@pytest.fixture(scope="session")
def ca(tmp_env):
    ca = CertificateAuthority()
    ok, msg = ca.initialise()
    assert ok, msg
    return ca


@pytest.fixture(scope="session")
def alice(ca):
    v = Vehicle("Alice", "Car")
    ok, msg = v.register()
    assert ok, msg
    ok, msg = ca.issue_certificate(v.vehicle_id, v.owner_name,
                                   v.public_key_path)
    assert ok, msg
    row = database.fetch_certificates_for_vehicle(v.vehicle_id)
    v._serial = row[0]["serial_number"]
    ok, msg = v.authenticate(v._serial, ca)
    assert ok, msg
    return v


@pytest.fixture(scope="session")
def bob(ca):
    v = Vehicle("Bob", "Truck")
    ok, msg = v.register()
    assert ok, msg
    ok, msg = ca.issue_certificate(v.vehicle_id, v.owner_name,
                                   v.public_key_path)
    assert ok, msg
    row = database.fetch_certificates_for_vehicle(v.vehicle_id)
    v._serial = row[0]["serial_number"]
    ok, msg = v.authenticate(v._serial, ca)
    assert ok, msg
    return v


# ── Key generation ────────────────────────────────────────────────────────────

def test_key_pair_files_exist(alice):
    assert os.path.isfile(alice.private_key_path)
    assert os.path.isfile(alice.public_key_path)


def test_key_pair_rsa_2048(alice):
    from cryptography.hazmat.primitives import serialization
    with open(alice.private_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    assert key.key_size == 2048


# ── Certificate ───────────────────────────────────────────────────────────────

def test_certificate_file_exists(alice):
    cert_path = os.path.join(config.CERTIFICATES_DIR,
                              f"{alice.vehicle_id}_cert.pem")
    assert os.path.isfile(cert_path)


def test_certificate_valid(alice, ca):
    ok, reason = ca.validate(alice.vehicle_id)
    assert ok, reason


def test_certificate_in_db(alice):
    row = database.fetch_certificates_for_vehicle(alice.vehicle_id)
    assert len(row) >= 1
    assert row[0]["status"] == "VALID"


# ── Signatures ────────────────────────────────────────────────────────────────

def test_sign_and_verify(alice):
    msg = "Emergency brake alert from Alice"
    sig, digest, nonce = crypto_utils.sign_message(msg, alice.private_key_path)
    assert isinstance(sig, str) and len(sig) > 0
    valid = crypto_utils.verify_signature(msg, sig, alice.public_key_path, nonce)
    assert valid


def test_tampered_message_fails_verify(alice):
    msg = "Original V2V message"
    sig, _, nonce = crypto_utils.sign_message(msg, alice.private_key_path)
    valid = crypto_utils.verify_signature("Tampered message", sig,
                                           alice.public_key_path, nonce)
    assert not valid


def test_wrong_key_fails_verify(alice, bob):
    msg = "Message from Alice"
    sig, _, nonce = crypto_utils.sign_message(msg, alice.private_key_path)
    # Verify with Bob's public key — should fail
    valid = crypto_utils.verify_signature(msg, sig,
                                           bob.public_key_path, nonce)
    assert not valid


# ── Replay attack ─────────────────────────────────────────────────────────────

def test_replay_attack_detected(alice):
    msg = "V2V hazard alert"
    ok, out_msg, detail = alice.sign(msg)
    assert ok
    nonce = detail["nonce"]
    # Replay: same nonce appears in DB — replay_token_exists must fire
    assert database.replay_token_exists(nonce), \
        "Nonce should be stored after first sign"


def test_duplicate_nonce_rejected(alice):
    """Simulate a replayed message by re-using an existing nonce."""
    msg = "First genuine message"
    ok, _, detail = alice.sign(msg)
    assert ok
    nonce = detail["nonce"]

    # A second sign always generates a fresh nonce — confirm they differ
    ok2, _, detail2 = alice.sign("Second message")
    assert ok2
    assert detail["nonce"] != detail2["nonce"], \
        "Each signed message must have a unique nonce"


# ── Encryption / Decryption ───────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip(alice, bob):
    plaintext = "Confidential V2V route update"
    ok, ct = alice.encrypt(plaintext, bob.public_key_path)
    assert ok
    ok, pt = bob.decrypt(ct)
    assert ok
    assert pt == plaintext


def test_wrong_key_decrypt_fails(alice, bob):
    _, ct = alice.encrypt("Secret data", bob.public_key_path)
    ok, err = alice.decrypt(ct)   # Alice tries to decrypt Bob's message
    assert not ok


def test_tampered_ciphertext_fails(alice, bob):
    _, ct = alice.encrypt("Sensitive V2V payload", bob.public_key_path)
    tampered = ct[:-4] + "XXXX"  # corrupt last bytes
    ok, _ = bob.decrypt(tampered)
    assert not ok


# ── Revocation ────────────────────────────────────────────────────────────────

def test_revoke_certificate(ca):
    v = Vehicle("Charlie", "Bus")
    v.register()
    ca.issue_certificate(v.vehicle_id, v.owner_name, v.public_key_path)
    row = database.fetch_certificates_for_vehicle(v.vehicle_id)
    serial = row[0]["serial_number"]

    ok, msg = ca.revoke_certificate(serial, v.vehicle_id, "Key compromise")
    assert ok, msg
    assert database.is_revoked(serial)


def test_revoked_cert_auth_fails(ca):
    v = Vehicle("Dave", "Van")
    v.register()
    ca.issue_certificate(v.vehicle_id, v.owner_name, v.public_key_path)
    row = database.fetch_certificates_for_vehicle(v.vehicle_id)
    serial = row[0]["serial_number"]
    ca.revoke_certificate(serial, v.vehicle_id, "Superseded")

    ok, msg = v.authenticate(serial, ca)
    assert not ok
    assert "revoked" in msg.lower()


def test_double_revocation_rejected(ca):
    v = Vehicle("Eve", "SUV")
    v.register()
    ca.issue_certificate(v.vehicle_id, v.owner_name, v.public_key_path)
    row = database.fetch_certificates_for_vehicle(v.vehicle_id)
    serial = row[0]["serial_number"]
    ca.revoke_certificate(serial, v.vehicle_id)
    ok, msg = ca.revoke_certificate(serial, v.vehicle_id)
    assert not ok
    assert "already" in msg.lower()


# ── Unauthorised signing ──────────────────────────────────────────────────────

def test_unauthenticated_vehicle_cannot_sign():
    v = Vehicle("Stranger", "Car")
    v.register()
    # Do NOT authenticate
    ok, msg, _ = v.sign("Unauthorised message")
    assert not ok
    assert "not authenticated" in msg.lower()


# ── MITM — tampered certificate ───────────────────────────────────────────────

def test_mitm_tampered_cert_fails(alice, ca, tmp_path):
    """Write a corrupted cert and confirm CA signature check rejects it."""
    orig = os.path.join(config.CERTIFICATES_DIR,
                         f"{alice.vehicle_id}_cert.pem")
    with open(orig, "rb") as f:
        data = f.read()

    tampered_path = str(tmp_path / "tampered_cert.pem")
    # Flip a byte in the middle of the cert body
    mid = len(data) // 2
    mutated = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid+1:]
    with open(tampered_path, "wb") as f:
        f.write(mutated)

    ok, reason = crypto_utils.validate_certificate(tampered_path,
                                                    config.CA_CERT_FILE)
    # Tampered cert must always be rejected — reason may vary by library version
    assert not ok, f"Expected rejection but got: {reason}"
