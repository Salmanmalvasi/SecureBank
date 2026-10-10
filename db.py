import os
import secrets
import sqlite3
import time
from werkzeug.security import generate_password_hash

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank.db")

# Demo secret for TOKEN-001. The firmware ships with the same value, so the
# real token works out of the box. Run provision.py to replace it.
DEMO_MASTER = "00112233445566778899aabbccddeeff" "ffeeddccbbaa99887766554433221100"


def connect():
    conn = sqlite3.connect(PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    d = connect()
    d.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        account TEXT PRIMARY KEY, name TEXT, pw_hash TEXT,
        device_id TEXT, balance REAL);
    CREATE TABLE IF NOT EXISTS devices(
        device_id TEXT PRIMARY KEY, master_hex TEXT,
        last_counter INTEGER DEFAULT -1, last_seen INTEGER);
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT, ts INTEGER,
        description TEXT, amount REAL, balance_after REAL);
    CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, account TEXT,
        event TEXT, detail TEXT, ip TEXT);
    """)
    if d.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        pw = generate_password_hash("bank123")
        d.executemany("INSERT INTO devices(device_id, master_hex) VALUES(?,?)", [
            ("TOKEN-001", DEMO_MASTER),
            ("TOKEN-002", secrets.token_hex(32)),
            ("TOKEN-003", secrets.token_hex(32)),
        ])
        d.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
            ("1001234567", "Salman", pw, "TOKEN-001", 48250.75),
            ("2002345678", "Raghav", pw, "TOKEN-002", 15200.00),
            ("3003456789", "Faizan", pw, "TOKEN-003", 9800.50),
        ])
        day = 86400
        now = int(time.time())
        rows = [
            (now - 10 * day, "Salary credit", 52000.00),
            (now - 9 * day, "Rent", -12000.00),
            (now - 8 * day, "UPI - Grocery store", -962.50),
            (now - 7 * day, "Electricity bill", -1840.00),
            (now - 5 * day, "ATM withdrawal", -5000.00),
            (now - 4 * day, "UPI - Restaurant", -1240.00),
            (now - 2 * day, "Mobile recharge", -399.00),
            (now - 1 * day, "Interest credit", 692.25),
        ]
        # work backwards so the last row ends at the current balance
        bal = 48250.75
        out = []
        for ts, desc, amt in reversed(rows):
            out.append((ts, desc, amt, round(bal, 2)))
            bal -= amt
        for ts, desc, amt, after in reversed(out):
            d.execute("INSERT INTO transactions(account,ts,description,amount,balance_after)"
                      " VALUES('1001234567',?,?,?,?)", (ts, desc, amt, after))
        d.commit()
    d.commit()
    d.close()
