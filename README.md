# 🔐 AutoTrust — PKI-Based Vehicle-to-Vehicle Secure Communication System

> ST6051CEM Practical Cryptography | Final Year Coursework

---

## Overview

AutoTrust is an open-source PKI tool that brings real-world security to
Vehicle-to-Vehicle (V2V) communication networks. It implements a complete
Public Key Infrastructure from a Root CA through to per-vehicle X.509
certificates, signed messages, and hybrid-encrypted payloads.

---

## Features

| Feature | Implementation |
|---|---|
| Key generation | RSA-2048 (public_exponent=65537) |
| Certificate Authority | Self-signed X.509 v3 Root CA |
| Vehicle certificates | X.509 v3, SHA-256, 365-day validity |
| Digital signatures | RSA-PSS / SHA-256, 32-byte random salt |
| Encryption | Hybrid: RSA-OAEP + AES-256-GCM |
| Secure key storage | PKCS#12 keystores (PBKDF2, 100k iterations) |
| Replay protection | UUID4 nonce + UTC timestamp per message |
| MITM defence | CA signature validation on every certificate |
| Certificate revocation | CRL stored in SQLite |
| Audit log | Immutable signed_messages table |

---

## Installation

```bash
# Clone / extract the project
cd AutoTrust

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 main.py

# Run tests
python3 -m pytest tests/ -v
```

---

## Project Structure

```
AutoTrust/
├── main.py            # Entry point
├── config.py          # Global configuration
├── database.py        # SQLite layer (4 tables)
├── crypto_utils.py    # All cryptographic operations
├── ca.py              # Certificate Authority
├── vehicle.py         # Vehicle entity
├── requirements.txt
├── gui/
│   ├── dashboard.py   # App shell + sidebar navigation
│   ├── theme.py       # Design system (colours, fonts)
│   ├── widgets.py     # Reusable UI components
│   └── pages/
│       ├── overview.py    # Dashboard KPIs
│       ├── register.py    # Vehicle registration
│       ├── certificate.py # Cert issuance + auth
│       ├── sign.py        # Message signing
│       ├── verify.py      # Signature verification
│       ├── encrypt.py     # Encrypt / decrypt
│       ├── revoke.py      # Certificate revocation
│       └── log_page.py    # Audit log
├── tests/
│   └── test_autotrust.py  # 16 test cases
├── certificates/      # PEM certificate files
├── keys/              # PEM key files + PKCS#12 keystores
├── messages/          # Saved message files
└── database/
    └── autotrust.db   # SQLite database
```

---

## Use Cases

### 1. Emergency Vehicle Priority (Confidentiality + Authentication)
An ambulance signs and encrypts a priority corridor request. Only the
traffic-management vehicle can decrypt it; the signature proves the
ambulance's identity and prevents spoofing.

### 2. Platooning Integrity (Non-repudiation + Anti-replay)
Trucks in a convoy sign every speed-change command. The replay-nonce
system ensures an attacker cannot re-inject an old "slow down" command
to cause a collision.

### 3. Certificate Revocation after Theft (Authentication)
A stolen vehicle's certificate is immediately revoked via the CRL.
All V2V participants reject any signed message from that vehicle,
preventing the attacker from participating in the network.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM (authenticated encryption) |
| Integrity | GCM auth tag + SHA-256 hash |
| Authentication | X.509 certificate chain + RSA-PSS signature |
| Non-repudiation | Only holder of private key can sign |
| Forward secrecy | Ephemeral AES session key per message |
| Anti-replay | UUID4 nonce stored and checked against DB |
| MITM defence | CA signature checked before any cert is trusted |

---

## License

MIT — open-source contribution, extend freely with attribution.
