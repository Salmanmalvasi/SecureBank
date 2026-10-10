"""Software stand-in for a token (useful for TOKEN-002/003 or if the hardware is away).
    python device_sim.py TOKEN-001
"""
import sys
import time
import db
import otp

dev = sys.argv[1] if len(sys.argv) > 1 else "TOKEN-001"
row = db.connect().execute("SELECT master_hex FROM devices WHERE device_id=?", (dev,)).fetchone()
if not row:
    sys.exit("Unknown device")
key = otp.derive_key(bytes.fromhex(row["master_hex"]), dev)
while True:
    left = otp.STEP - int(time.time()) % otp.STEP
    print(f"\r{dev}  OTP: {otp.totp(key, otp.current_counter())}  (changes in {left:2d}s) ",
          end="", flush=True)
    time.sleep(1)
