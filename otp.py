"""HKDF (RFC 5869) + TOTP-style OTP with HMAC-SHA256 (RFC 4226 / 6238 approach).

The ESP32 firmware must follow exactly the same steps:
  1. key  = HKDF-SHA256(master_secret, salt=device_id, info="OTP-KEY", length=32)
  2. ctr  = floor(unix_time / 30), as 8 bytes big-endian
  3. mac  = HMAC-SHA256(key, ctr)
  4. dynamic truncation -> 6 digits
"""
import hashlib
import hmac
import struct
import time

STEP = 30      # seconds per OTP
DIGITS = 6
WINDOW = 1     # accept +/- 1 step to tolerate RTC clock drift


def hkdf(master: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, master, hashlib.sha256).digest()          # extract
    okm, block = b"", b""
    for i in range(1, -(-length // 32) + 1):                        # expand
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


def derive_key(master: bytes, device_id: str) -> bytes:
    return hkdf(master, device_id.encode(), b"OTP-KEY", 32)


def totp(key: bytes, counter: int) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** DIGITS).zfill(DIGITS)


def current_counter(now=None) -> int:
    return int((now if now is not None else time.time()) // STEP)


def verify(master: bytes, device_id: str, submitted: str, last_used: int = -1):
    """Return (ok, counter_used, reason)."""
    key = derive_key(master, device_id)
    now = current_counter()
    for c in range(now - WINDOW, now + WINDOW + 1):
        if hmac.compare_digest(totp(key, c), submitted):
            if c <= last_used:
                return False, last_used, "This code was already used."
            return True, c, "ok"
    return False, last_used, "Invalid or expired code."
