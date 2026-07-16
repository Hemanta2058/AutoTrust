"""
demo.py — AutoTrust Automated Demo Script
==========================================
Demonstrates all PKI features without the GUI.
Run: python demo.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import config
import database
import crypto_utils
from ca import CertificateAuthority
from vehicle import Vehicle

def run_demo():
    print("=" * 60)
    print("  AutoTrust — PKI V2V Demo")
    print("=" * 60)

    # Setup
    config.ensure_directories()
    database.initialise()

    # 1. Initialise CA
    print("\n[1] Initialising Certificate Authority...")
    ca = CertificateAuthority()
    ok, msg = ca.initialise()
    print(f"    {msg}")

    # 2. Register vehicles
    print("\n[2] Registering vehicles...")
    alice = Vehicle("Alice Johnson", "Car")
    alice.register()
    print(f"    Alice registered: {alice.vehicle_id}")

    bob = Vehicle("Bob Smith", "Truck")
    bob.register()
    print(f"    Bob registered:   {bob.vehicle_id}")

    # 3. Issue certificates
    print("\n[3] Issuing X.509 certificates...")
    ca.issue_certificate(alice.vehicle_id, alice.owner_name, alice.public_key_path)
    ca.issue_certificate(bob.vehicle_id, bob.owner_name, bob.public_key_path)
    print("    Certificates issued for Alice and Bob.")

    # 4. Authenticate
    print("\n[4] Authenticating Alice...")
    row = database.fetch_certificates_for_vehicle(alice.vehicle_id)
    serial = row[0]["serial_number"]
    ok, msg = alice.authenticate(serial, ca)
    print(f"    {msg}")

    # 5. Sign message
    print("\n[5] Alice signs a V2V message...")
    ok, msg, detail = alice.sign("Emergency brake warning — hazard ahead on Route 7", bob.vehicle_id)
    print(f"    Message ID : {detail.get('message_id', '')}")
    print(f"    SHA-256    : {detail.get('hash', '')[:32]}...")
    print(f"    Signature  : {detail.get('signature', '')[:40]}...")

    # 6. Verify signature
    print("\n[6] Verifying signature...")
    msg_row = database.fetch_all_messages()[0]
    pub_path = os.path.join(config.KEYS_DIR, f"{alice.vehicle_id}_public.pem")
    valid = crypto_utils.verify_signature(
        msg_row["plaintext"], msg_row["signature"],
        pub_path, msg_row["replay_token"]
    )
    print(f"    Signature valid: {valid}")

    # 7. Encrypt and decrypt
    print("\n[7] Alice encrypts a message for Bob...")
    ok, ct = alice.encrypt("Confidential route: avoid highway 9", bob.public_key_path)
    print(f"    Ciphertext: {ct[:50]}...")
    ok, pt = bob.decrypt(ct)
    print(f"    Decrypted : {pt}")

    # 8. Replay attack demo
    print("\n[8] Replay attack detection...")
    nonce = msg_row["replay_token"]
    already_used = database.replay_token_exists(nonce)
    print(f"    Nonce already used: {already_used} — replay blocked!")

    # 9. Revoke certificate
    print("\n[9] Revoking Alice's certificate...")
    ok, msg = ca.revoke_certificate(serial, alice.vehicle_id, "Key compromise")
    print(f"    {msg}")

    # 10. Try to sign after revocation
    print("\n[10] Alice tries to sign after revocation...")
    alice2 = Vehicle.from_db(alice.vehicle_id)
    ok, msg, _ = alice2.authenticate(serial, ca), "", {}
    auth_ok, auth_msg = alice2.authenticate(serial, ca)
    print(f"    Result: {auth_msg}")

    print("\n" + "=" * 60)
    print("  Demo complete! All PKI features demonstrated.")
    print("=" * 60)

if __name__ == "__main__":
    run_demo()