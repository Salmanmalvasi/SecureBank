import csv
import io
import math
import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash

import db
import otp

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

keyfile = os.path.join(BASE, "secret.key")
if not os.path.exists(keyfile):
    with open(keyfile, "w") as f:
        f.write(secrets.token_hex(32))
with open(keyfile) as f:
    app.secret_key = f.read().strip()
app.permanent_session_lifetime = timedelta(minutes=5)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
db.init()

STEP_UP_LIMIT = 10000        # transfers at or above this need a fresh OTP
MAX_TRIES, LOCK_SECONDS = 3, 60
PUSH_VALID = 45              # seconds a Wi-Fi pushed code stays claimable
attempts = {}                # account -> [fail count, locked_until]
pushes = {}                  # device_id -> time of last verified push


# ---------------------------------------------------------------- helpers
def get_db():
    if "db" not in g:
        g.db = db.connect()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def audit(acct, event, detail=""):
    d = get_db()
    d.execute("INSERT INTO audit(ts,account,event,detail,ip) VALUES(?,?,?,?,?)",
              (int(time.time()), acct, event, detail, request.remote_addr))
    d.commit()


def get_user(acct):
    return get_db().execute("SELECT * FROM users WHERE account=?", (acct,)).fetchone()


def is_locked(acct):
    rec = attempts.get(acct)
    return bool(rec and rec[1] > time.time())


def register_fail(acct):
    rec = attempts.setdefault(acct, [0, 0])
    rec[0] += 1
    if rec[0] >= MAX_TRIES:
        rec[0], rec[1] = 0, time.time() + LOCK_SECONDS
        audit(acct, "locked", f"{LOCK_SECONDS}s lockout")


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login"))
        g.user = get_user(session["user"])
        return f(*a, **k)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST" and request.path != "/api/push":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF")
        if not sent or sent != session.get("csrf"):
            abort(400)


@app.template_filter("money")
def money(v):
    return "{:,.2f}".format(v)


@app.template_filter("dt")
def dt(ts):
    return time.strftime("%d %b %Y, %H:%M", time.localtime(ts))


def check_code(device_id, code):
    """Verify an OTP for a device; consume it on success (replay protection)."""
    d = get_db()
    dev = d.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
    if not dev:
        return False, "Unknown device."
    if not (code.isdigit() and len(code) == 6):
        return False, "Enter the 6-digit code."
    ok, ctr, why = otp.verify(bytes.fromhex(dev["master_hex"]), device_id, code,
                              dev["last_counter"])
    if ok:
        d.execute("UPDATE devices SET last_counter=?, last_seen=? WHERE device_id=?",
                  (ctr, int(time.time()), device_id))
        d.commit()
    return ok, why


def claim_push(device_id):
    t = pushes.pop(device_id, None)
    return bool(t and time.time() - t < PUSH_VALID)


def finish_login(acct):
    audit(acct, "login_ok")
    attempts.pop(acct, None)
    session.clear()
    session.permanent = True
    session["user"] = acct


def do_transfer(src, t):
    d = get_db()
    now = int(time.time())
    with d:
        s = d.execute("SELECT balance FROM users WHERE account=?", (src,)).fetchone()
        if s["balance"] < t["amount"]:
            return False
        nb = round(s["balance"] - t["amount"], 2)
        d.execute("UPDATE users SET balance=? WHERE account=?", (nb, src))
        desc = f"Transfer to {t['to']}" + (f" - {t['note']}" if t["note"] else "")
        d.execute("INSERT INTO transactions(account,ts,description,amount,balance_after)"
                  " VALUES(?,?,?,?,?)", (src, now, desc, -t["amount"], nb))
        r = d.execute("SELECT balance FROM users WHERE account=?", (t["to"],)).fetchone()
        if r:
            rb = round(r["balance"] + t["amount"], 2)
            d.execute("UPDATE users SET balance=? WHERE account=?", (rb, t["to"]))
            d.execute("INSERT INTO transactions(account,ts,description,amount,balance_after)"
                      " VALUES(?,?,?,?,?)", (t["to"], now, f"Transfer from {src}", t["amount"], rb))
    audit(src, "transfer", f"{t['amount']:.2f} to {t['to']}")
    return True


# ------------------------------------------------------------------ login
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        acct = request.form.get("account", "").strip()
        pw = request.form.get("password", "")
        user = get_user(acct)
        if is_locked(acct):
            error = "Too many attempts. Try again in a minute."
        elif user and check_password_hash(user["pw_hash"], pw):
            audit(acct, "password_ok")
            session.clear()
            session.permanent = True
            session["pending"] = acct
            return redirect(url_for("verify_otp"))
        else:
            register_fail(acct)
            audit(acct, "password_fail")
            error = "Incorrect account number or password."
    return render_template("login.html", error=error)


@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    acct = session.get("pending")
    if not acct:
        return redirect(url_for("login"))
    user = get_user(acct)
    error = None
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if is_locked(acct):
            error = "Too many attempts. Try again in a minute."
        else:
            ok, why = check_code(user["device_id"], code)
            if ok:
                finish_login(acct)
                return redirect(url_for("dashboard"))
            register_fail(acct)
            audit(acct, "otp_fail", why)
            error = why
    return render_template("otp.html", error=error, device=user["device_id"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------- the bank
@app.route("/dashboard")
@login_required
def dashboard():
    recent = get_db().execute(
        "SELECT * FROM transactions WHERE account=? ORDER BY ts DESC, id DESC LIMIT 5",
        (g.user["account"],)).fetchall()
    inflow = get_db().execute(
        "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE account=? AND amount>0 AND ts>?",
        (g.user["account"], time.time() - 30 * 86400)).fetchone()[0]
    outflow = get_db().execute(
        "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE account=? AND amount<0 AND ts>?",
        (g.user["account"], time.time() - 30 * 86400)).fetchone()[0]
    return render_template("dashboard.html", user=g.user, recent=recent,
                           inflow=inflow, outflow=-outflow)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    error = None
    if request.method == "POST":
        to = request.form.get("to", "").strip()
        note = request.form.get("note", "").strip()[:40]
        try:
            amount = round(float(request.form.get("amount", "0")), 2)
        except ValueError:
            amount = 0
        if not (to.isdigit() and 6 <= len(to) <= 14):
            error = "Enter a valid account number (6-14 digits)."
        elif to == g.user["account"]:
            error = "You cannot transfer to your own account."
        elif not math.isfinite(amount) or amount <= 0:
            error = "Enter an amount greater than zero."
        elif amount > g.user["balance"]:
            error = "Insufficient balance."
        else:
            t = {"to": to, "amount": amount, "note": note}
            if amount >= STEP_UP_LIMIT:
                session["transfer"] = t
                audit(g.user["account"], "transfer_needs_otp", f"{amount:.2f} to {to}")
                return redirect(url_for("transfer_confirm"))
            do_transfer(g.user["account"], t)
            flash(f"Transferred Rs. {amount:,.2f} to {to}.")
            return redirect(url_for("history"))
    return render_template("transfer.html", user=g.user, error=error, limit=STEP_UP_LIMIT)


@app.route("/transfer/confirm", methods=["GET", "POST"])
@login_required
def transfer_confirm():
    t = session.get("transfer")
    if not t:
        return redirect(url_for("transfer"))
    acct = g.user["account"]
    error = None
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if is_locked(acct):
            error = "Too many attempts. Try again in a minute."
        else:
            ok, why = check_code(g.user["device_id"], code)
            if ok:
                session.pop("transfer")
                if do_transfer(acct, t):
                    flash(f"Transferred Rs. {t['amount']:,.2f} to {t['to']}.")
                else:
                    flash("Transfer failed: insufficient balance.")
                return redirect(url_for("history"))
            register_fail(acct)
            audit(acct, "otp_fail", why + " (transfer)")
            error = why
    return render_template("confirm.html", t=t, error=error, device=g.user["device_id"])


@app.route("/transfer/cancel", methods=["POST"])
@login_required
def transfer_cancel():
    session.pop("transfer", None)
    return redirect(url_for("transfer"))


def history_query(acct, kind, q):
    sql = "FROM transactions WHERE account=?"
    args = [acct]
    if kind == "credit":
        sql += " AND amount>0"
    elif kind == "debit":
        sql += " AND amount<0"
    if q:
        sql += " AND description LIKE ?"
        args.append(f"%{q}%")
    return sql, args


@app.route("/history")
@login_required
def history():
    kind = request.args.get("type", "all")
    q = request.args.get("q", "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    sql, args = history_query(g.user["account"], kind, q)
    total = get_db().execute("SELECT COUNT(*) " + sql, args).fetchone()[0]
    rows = get_db().execute("SELECT * " + sql + " ORDER BY ts DESC, id DESC LIMIT 10 OFFSET ?",
                            args + [(page - 1) * 10]).fetchall()
    return render_template("history.html", rows=rows, kind=kind, q=q, page=page,
                           pages=max(1, -(-total // 10)))


@app.route("/history.csv")
@login_required
def history_csv():
    sql, args = history_query(g.user["account"], "all", "")
    rows = get_db().execute("SELECT * " + sql + " ORDER BY ts DESC", args).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Date", "Description", "Amount", "Balance"])
    for r in rows:
        desc = r["description"]
        if desc[:1] in "=+-@":
            desc = "'" + desc
        w.writerow([dt(r["ts"]), desc, r["amount"], r["balance_after"]])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=statement.csv"})


@app.route("/security")
@login_required
def security():
    dev = get_db().execute("SELECT * FROM devices WHERE device_id=?",
                           (g.user["device_id"],)).fetchone()
    log = get_db().execute("SELECT * FROM audit WHERE account=? ORDER BY id DESC LIMIT 15",
                           (g.user["account"],)).fetchall()
    return render_template("security.html", user=g.user, dev=dev, log=log)


# ------------------------------------------------------- hardware / API
@app.route("/api/push", methods=["POST"])
def api_push():
    """ESP32 over Wi-Fi: POST {"device": "TOKEN-001", "otp": "123456"}."""
    data = request.get_json(silent=True) or {}
    device = str(data.get("device", ""))
    ok, why = check_code(device, str(data.get("otp", "")))
    if ok:
        pushes[device] = time.time()
    return jsonify(ok=ok, reason=why), (200 if ok else 401)


@app.route("/api/poll", methods=["POST"])
def api_poll():
    """The OTP page polls this; a Wi-Fi push completes the pending step."""
    if session.get("pending"):
        acct = session["pending"]
        if claim_push(get_user(acct)["device_id"]):
            finish_login(acct)
            return jsonify(done=True, next=url_for("dashboard"))
    elif session.get("user") and session.get("transfer"):
        user = get_user(session["user"])
        if claim_push(user["device_id"]):
            t = session.pop("transfer")
            ok = do_transfer(user["account"], t)
            flash(f"Transferred Rs. {t['amount']:,.2f} to {t['to']}." if ok
                  else "Transfer failed: insufficient balance.")
            return jsonify(done=True, next=url_for("history"))
    return jsonify(done=False)


if __name__ == "__main__":
    # 0.0.0.0 so the ESP32 on the same Wi-Fi can reach the server
    app.run(host="0.0.0.0", port=5000, debug=False)
