"""
database.py — AutoTrust SQLite Database Layer
=============================================
Manages all persistence: connection handling, schema creation,
and CRUD helpers used by ca.py, vehicle.py, and the GUI.

Tables
------
  vehicles              — registered V2V network participants
  certificates          — issued X.509 certificate metadata
  revoked_certificates  — Certificate Revocation List (CRL)
  signed_messages       — audit log of all signed V2V messages

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, Optional

import config

log = logging.getLogger(__name__)

# ── Schema ───────────────────────────────────────────────────────────────────

_DDL_VEHICLES = """
CREATE TABLE IF NOT EXISTS vehicles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id       TEXT    NOT NULL UNIQUE,
    owner_name       TEXT    NOT NULL,
    vehicle_type     TEXT    NOT NULL,
    public_key_path  TEXT    DEFAULT '',
    keystore_path    TEXT    DEFAULT '',
    registered_at    TEXT    NOT NULL,
    is_active        INTEGER NOT NULL DEFAULT 1
);"""

_DDL_CERTIFICATES = """
CREATE TABLE IF NOT EXISTS certificates (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number TEXT    NOT NULL UNIQUE,
    vehicle_id    TEXT    NOT NULL,
    issued_by     TEXT    NOT NULL,
    issued_at     TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    cert_path     TEXT    DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'VALID',
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
);"""

_DDL_REVOKED = """
CREATE TABLE IF NOT EXISTS revoked_certificates (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number     TEXT NOT NULL UNIQUE,
    vehicle_id        TEXT NOT NULL,
    revoked_at        TEXT NOT NULL,
    revocation_reason TEXT DEFAULT 'Unspecified',
    revoked_by        TEXT DEFAULT 'CA Operator',
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
);"""

_DDL_MESSAGES = """
CREATE TABLE IF NOT EXISTS signed_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id   TEXT NOT NULL UNIQUE,
    sender_id    TEXT NOT NULL,
    recipient_id TEXT DEFAULT '',
    plaintext    TEXT NOT NULL,
    message_hash TEXT NOT NULL,
    signature    TEXT NOT NULL,
    signed_at    TEXT NOT NULL,
    is_verified  INTEGER NOT NULL DEFAULT 0,
    replay_token TEXT DEFAULT '',
    FOREIGN KEY (sender_id) REFERENCES vehicles(vehicle_id)
);"""


# ── Connection context manager ───────────────────────────────────────────────

@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a configured SQLite connection; commit or rollback automatically."""
    con = sqlite3.connect(config.DATABASE_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA journal_mode = WAL;")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ── Initialisation ───────────────────────────────────────────────────────────

def initialise() -> None:
    """Create all tables (idempotent — safe to call on every startup)."""
    with _conn() as con:
        for ddl in (_DDL_VEHICLES, _DDL_CERTIFICATES, _DDL_REVOKED, _DDL_MESSAGES):
            con.execute(ddl)
    log.info("Database ready: %s", config.DATABASE_PATH)


# ── Vehicle helpers ──────────────────────────────────────────────────────────

def insert_vehicle(vehicle_id: str, owner_name: str, vehicle_type: str,
                   public_key_path: str = "", keystore_path: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as con:
        con.execute(
            "INSERT INTO vehicles (vehicle_id,owner_name,vehicle_type,"
            "public_key_path,keystore_path,registered_at) VALUES (?,?,?,?,?,?)",
            (vehicle_id, owner_name, vehicle_type, public_key_path, keystore_path, now)
        )


def fetch_vehicle(vehicle_id: str) -> Optional[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM vehicles WHERE vehicle_id=?", (vehicle_id,)
        ).fetchone()


def fetch_all_vehicles() -> list:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM vehicles ORDER BY registered_at DESC"
        ).fetchall()


def update_vehicle_keys(vehicle_id: str, public_key_path: str,
                        keystore_path: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE vehicles SET public_key_path=?, keystore_path=? WHERE vehicle_id=?",
            (public_key_path, keystore_path, vehicle_id)
        )


# ── Certificate helpers ──────────────────────────────────────────────────────

def insert_certificate(serial: str, vehicle_id: str, issued_by: str,
                       issued_at: str, expires_at: str, cert_path: str) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO certificates (serial_number,vehicle_id,issued_by,"
            "issued_at,expires_at,cert_path) VALUES (?,?,?,?,?,?)",
            (serial, vehicle_id, issued_by, issued_at, expires_at, cert_path)
        )


def fetch_certificate(serial: str) -> Optional[sqlite3.Row]:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM certificates WHERE serial_number=?", (serial,)
        ).fetchone()


def fetch_certificates_for_vehicle(vehicle_id: str) -> list:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM certificates WHERE vehicle_id=? ORDER BY issued_at DESC",
            (vehicle_id,)
        ).fetchall()


def fetch_all_certificates() -> list:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM certificates ORDER BY issued_at DESC"
        ).fetchall()


def set_certificate_status(serial: str, status: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE certificates SET status=? WHERE serial_number=?",
            (status, serial)
        )


# ── Revocation helpers ───────────────────────────────────────────────────────

def insert_revocation(serial: str, vehicle_id: str,
                      reason: str = "Unspecified",
                      revoked_by: str = "CA Operator") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as con:
        con.execute(
            "INSERT INTO revoked_certificates (serial_number,vehicle_id,"
            "revoked_at,revocation_reason,revoked_by) VALUES (?,?,?,?,?)",
            (serial, vehicle_id, now, reason, revoked_by)
        )
        con.execute(
            "UPDATE certificates SET status='REVOKED' WHERE serial_number=?",
            (serial,)
        )


def is_revoked(serial: str) -> bool:
    with _conn() as con:
        row = con.execute(
            "SELECT 1 FROM revoked_certificates WHERE serial_number=?", (serial,)
        ).fetchone()
        return row is not None


def fetch_all_revoked() -> list:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM revoked_certificates ORDER BY revoked_at DESC"
        ).fetchall()


# ── Message helpers ──────────────────────────────────────────────────────────

def insert_message(message_id: str, sender_id: str, plaintext: str,
                   message_hash: str, signature: str,
                   recipient_id: str = "", replay_token: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as con:
        con.execute(
            "INSERT INTO signed_messages (message_id,sender_id,recipient_id,"
            "plaintext,message_hash,signature,signed_at,replay_token) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (message_id, sender_id, recipient_id, plaintext,
             message_hash, signature, now, replay_token)
        )


def mark_message_verified(message_id: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE signed_messages SET is_verified=1 WHERE message_id=?",
            (message_id,)
        )


def replay_token_exists(token: str) -> bool:
    """Detect replay attacks — returns True if token was used before."""
    with _conn() as con:
        row = con.execute(
            "SELECT 1 FROM signed_messages WHERE replay_token=?", (token,)
        ).fetchone()
        return row is not None


def fetch_all_messages() -> list:
    with _conn() as con:
        return con.execute(
            "SELECT * FROM signed_messages ORDER BY signed_at DESC"
        ).fetchall()


# ── Dashboard stats ──────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Return counts for the dashboard overview cards."""
    with _conn() as con:
        def count(table, where="1=1"):
            return con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {where}"
            ).fetchone()[0]
        return {
            "vehicles":     count("vehicles"),
            "certificates": count("certificates", "status='VALID'"),
            "revoked":      count("revoked_certificates"),
            "messages":     count("signed_messages"),
        }
