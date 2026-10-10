"""Create a fresh random 256-bit master secret for a device (project step 1:
provisioning). Updates the database and prints the line to paste in the firmware.

    python provision.py TOKEN-001
"""
import secrets
import sys
import db

db.init()
dev = sys.argv[1] if len(sys.argv) > 1 else "TOKEN-001"
secret = secrets.token_bytes(32)
d = db.connect()
cur = d.execute("UPDATE devices SET master_hex=?, last_counter=-1 WHERE device_id=?",
                (secret.hex(), dev))
if cur.rowcount == 0:
    sys.exit(f"Unknown device {dev}")
d.commit()
arr = ", ".join(f"0x{b:02x}" for b in secret)
print(f"Updated {dev} in database.\n\nPaste into otp_token.ino and re-upload:\n")
print(f"#define DEVICE_ID \"{dev}\"")
print(f"static const uint8_t MASTER_SECRET[32] = {{ {arr} }};")
