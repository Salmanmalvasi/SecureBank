import csv
import io
import math
import os
import secrets
import time
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

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

STEP_UP_LIMIT = 0            # every transfer requires OTP verification
MAX_TRIES, LOCK_SECONDS = 3, 60
NEW_RECIPIENT_LIMIT = 10000.00        # above this, a new recipient must be a saved payee...
NEW_RECIPIENT_DELAY = 10 * 60         # ...for at least this many seconds
DAILY_TRANSFER_LIMIT = 100000.00      # total outgoing transfers per rolling 24 hours
MAX_PAYEES = 20
SHOW_DEMO_HINT = os.environ.get("SECUREBANK_DEMO") == "1"   # login-page demo credentials hint
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


@app.context_processor
def inject_globals():
    return {"session_seconds": int(app.permanent_session_lifetime.total_seconds()),
            "show_demo_hint": SHOW_DEMO_HINT}


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



# ------------------------------------------------- extra feature helpers
def sent_last_24h(acct):
    return get_db().execute(
        "SELECT COALESCE(SUM(-amount),0) FROM transactions WHERE account=? AND amount<0"
        " AND description LIKE 'Transfer to %' AND ts>?",
        (acct, time.time() - 86400)).fetchone()[0]


def recipient_status(acct, to):
    """('trusted'|'cooling'|'new', seconds_left) for a recipient account."""
    d = get_db()
    paid = d.execute(
        "SELECT 1 FROM transactions WHERE account=? AND amount<0 AND"
        " (description=? OR description LIKE ?) LIMIT 1",
        (acct, f"Transfer to {to}", f"Transfer to {to} - %")).fetchone()
    if paid:
        return "trusted", 0
    b = d.execute("SELECT created_ts FROM beneficiaries WHERE account=? AND to_account=?",
                  (acct, to)).fetchone()
    if not b:
        return "new", NEW_RECIPIENT_DELAY
    left = b["created_ts"] + NEW_RECIPIENT_DELAY - int(time.time())
    return ("trusted", 0) if left <= 0 else ("cooling", left)


def monthly_summary(acct, months=6):
    now = datetime.now()
    keys, y, m = [], now.year, now.month
    for _ in range(months):
        keys.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    keys.reverse()
    rows = get_db().execute(
        "SELECT strftime('%Y-%m', ts, 'unixepoch', 'localtime') k,"
        " SUM(CASE WHEN amount>0 THEN amount ELSE 0 END) i,"
        " SUM(CASE WHEN amount<0 THEN -amount ELSE 0 END) o"
        " FROM transactions WHERE account=? GROUP BY k", (acct,)).fetchall()
    data = {r["k"]: (r["i"] or 0, r["o"] or 0) for r in rows}
    out = []
    for y, m in keys:
        i, o = data.get(f"{y:04d}-{m:02d}", (0, 0))
        out.append({"label": datetime(y, m, 1).strftime("%b %Y"), "in": i, "out": o})
    peak = max([x["in"] for x in out] + [x["out"] for x in out] + [0]) or 1
    for x in out:
        x["in_pct"] = round(x["in"] / peak * 100, 1)
        x["out_pct"] = round(x["out"] / peak * 100, 1)
    return out


def parse_transfer_desc(desc):
    rest = desc[len("Transfer to "):]
    to, _, note = rest.partition(" - ")
    return to, note


def get_receipt(acct, tid):
    r = get_db().execute(
        "SELECT * FROM transactions WHERE id=? AND account=? AND amount<0"
        " AND description LIKE 'Transfer to %'", (tid, acct)).fetchone()
    if not r:
        return None
    to, note = parse_transfer_desc(r["description"])
    b = get_db().execute("SELECT nickname FROM beneficiaries WHERE account=? AND to_account=?",
                         (acct, to)).fetchone()
    return {"id": r["id"], "ref": f"SB{r['id']:08d}", "ts": r["ts"], "to": to, "note": note,
            "amount": -r["amount"], "balance_after": r["balance_after"],
            "nickname": b["nickname"] if b else ""}


def pdf_response(story, filename, title):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, title=title, author="SecureBank",
                      leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40).build(story)
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


def pdf_styles():
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    ss = getSampleStyleSheet()
    return {
        "h": ParagraphStyle("h", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=20,
                            alignment=0, textColor="#142B4A", spaceAfter=2),
        "sub": ParagraphStyle("sub", parent=ss["Normal"], fontSize=9, textColor="#68758A",
                              leading=13),
        "cell": ParagraphStyle("cell", parent=ss["Normal"], fontSize=8.5, leading=11),
    }


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
    d = get_db()
    logins = d.execute("SELECT ts, ip FROM audit WHERE account=? AND event='login_ok'"
                       " ORDER BY id DESC LIMIT 2", (g.user["account"],)).fetchall()
    last_login = logins[1] if len(logins) > 1 else None
    failed_since = 0
    if last_login:
        failed_since = d.execute(
            "SELECT COUNT(*) FROM audit WHERE account=? AND event IN ('password_fail','otp_fail')"
            " AND ts>?", (g.user["account"], last_login["ts"])).fetchone()[0]
    return render_template("dashboard.html", user=g.user, recent=recent,
                           inflow=inflow, outflow=-outflow, last_login=last_login,
                           failed_since=failed_since,
                           monthly=monthly_summary(g.user["account"]))


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
        elif amount > max(DAILY_TRANSFER_LIMIT - sent_last_24h(g.user["account"]), 0):
            left = max(DAILY_TRANSFER_LIMIT - sent_last_24h(g.user["account"]), 0)
            error = (f"This would exceed your daily transfer limit of Rs. {DAILY_TRANSFER_LIMIT:,.0f}. "
                     f"You can send up to Rs. {left:,.2f} more in the next 24 hours.")
        elif amount > NEW_RECIPIENT_LIMIT and recipient_status(g.user["account"], to)[0] != "trusted":
            status, wait = recipient_status(g.user["account"], to)
            if status == "cooling":
                error = (f"This payee was saved recently. Transfers above Rs. {NEW_RECIPIENT_LIMIT:,.0f} "
                         f"unlock in about {-(-wait // 60)} minute(s).")
            else:
                error = (f"Transfers above Rs. {NEW_RECIPIENT_LIMIT:,.0f} to a new recipient need the "
                         f"recipient saved as a payee for {NEW_RECIPIENT_DELAY // 60} minutes first. "
                         "Save them on the Payees page, or send a smaller amount.")
        else:
            t = {"to": to, "amount": amount, "note": note}
            # Every transfer must be confirmed with a fresh OTP.
            session["transfer"] = t
            audit(g.user["account"], "transfer_needs_otp", f"{amount:.2f} to {to}")
            return redirect(url_for("transfer_confirm"))
    payees = get_db().execute("SELECT * FROM beneficiaries WHERE account=? ORDER BY nickname COLLATE NOCASE",
                              (g.user["account"],)).fetchall()
    daily_left = max(DAILY_TRANSFER_LIMIT - sent_last_24h(g.user["account"]), 0)
    return render_template("transfer.html", user=g.user, error=error, limit=STEP_UP_LIMIT,
                           payees=payees, daily_left=daily_left,
                           new_limit=NEW_RECIPIENT_LIMIT, new_delay=NEW_RECIPIENT_DELAY // 60)


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
                    tid = get_db().execute(
                        "SELECT id FROM transactions WHERE account=? AND amount<0 ORDER BY id DESC LIMIT 1",
                        (acct,)).fetchone()
                    if tid:
                        return redirect(url_for("receipt", tid=tid["id"]))
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


def parse_day(s, next_day=False):
    """YYYY-MM-DD -> local-midnight unix time (or the following midnight)."""
    try:
        d = datetime.strptime(s, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None
    if next_day:
        d += timedelta(days=1)
    return int(time.mktime(d.timetuple()))


def history_query(acct, kind, q, d_from=None, d_to=None):
    sql = "FROM transactions WHERE account=?"
    args = [acct]
    start, end = parse_day(d_from), parse_day(d_to, next_day=True)
    if start is not None:
        sql += " AND ts>=?"
        args.append(start)
    if end is not None:
        sql += " AND ts<?"
        args.append(end)
    if kind == "credit":
        sql += " AND amount>0"
    elif kind == "debit":
        sql += " AND amount<0"
    if q:
        sql += " AND description LIKE ?"
        args.append(f"%{q}%")
    return sql, args


def clean_day(s):
    s = (s or "").strip()
    return s if parse_day(s) is not None else ""


@app.route("/history")
@login_required
def history():
    kind = request.args.get("type", "all")
    q = request.args.get("q", "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    d_from, d_to = clean_day(request.args.get("from")), clean_day(request.args.get("to"))
    sql, args = history_query(g.user["account"], kind, q, d_from, d_to)
    total = get_db().execute("SELECT COUNT(*) " + sql, args).fetchone()[0]
    rows = get_db().execute("SELECT * " + sql + " ORDER BY ts DESC, id DESC LIMIT 10 OFFSET ?",
                            args + [(page - 1) * 10]).fetchall()
    base_args = {"type": kind, "q": q, "from": d_from or None, "to": d_to or None}
    return render_template("history.html", rows=rows, kind=kind, q=q, page=page,
                           pages=max(1, -(-total // 10)), d_from=d_from, d_to=d_to,
                           base_args=base_args)


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
    d = get_db()

    dev = d.execute(
        "SELECT * FROM devices WHERE device_id=?",
        (g.user["device_id"],)
    ).fetchone()

    log = d.execute(
        "SELECT * FROM audit WHERE account=? ORDER BY id DESC LIMIT 15",
        (g.user["account"],)
    ).fetchall()

    auth_status = d.execute(
        """SELECT event, detail, ts FROM audit
           WHERE account=? AND event IN ('otp_fail', 'login_ok')
           ORDER BY id DESC LIMIT 1""",
        (g.user["account"],)
    ).fetchone()

    now = time.time()

    def count(event, secs):
        return d.execute("SELECT COUNT(*) FROM audit WHERE account=? AND event=? AND ts>?",
                         (g.user["account"], event, now - secs)).fetchone()[0]

    fail24, fail7 = count("otp_fail", 86400), count("otp_fail", 7 * 86400)
    health = {"fail24": fail24, "fail7": fail7, "locks": count("locked", 30 * 86400),
              "state": "connected" if fail24 == 0 else ("warning" if fail24 < 3 else "disconnected"),
              "label": "No recent failures" if fail24 == 0 else
                       ("Some failed codes" if fail24 < 3 else "Repeated failed codes")}

    return render_template(
        "security.html",
        user=g.user,
        dev=dev,
        log=log,
        auth_status=auth_status,
        health=health
    )


# ------------------------------------------------------------ receipts
@app.route("/receipt/<int:tid>")
@login_required
def receipt(tid):
    r = get_receipt(g.user["account"], tid)
    if not r:
        abort(404)
    return render_template("receipt.html", r=r, user=g.user)


@app.route("/receipt/<int:tid>.pdf")
@login_required
def receipt_pdf(tid):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    r = get_receipt(g.user["account"], tid)
    if not r:
        abort(404)
    st = pdf_styles()
    rows = [["Reference", r["ref"]], ["Date", dt(r["ts"])],
            ["From account", g.user["account"]],
            ["To account", r["to"] + (f" ({r['nickname']})" if r["nickname"] else "")],
            ["Amount", f"Rs. {r['amount']:,.2f}"],
            ["Balance after transfer", f"Rs. {r['balance_after']:,.2f}"]]
    if r["note"]:
        rows.append(["Note", r["note"]])
    rows = [[Paragraph(esc(k), st["sub"]), Paragraph(esc(v), st["cell"])] for k, v in rows]
    t = Table(rows, colWidths=[150, 340])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), .5, "#E3E9F2"),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story = [Paragraph("SecureBank", st["h"]), Paragraph("Transfer receipt", st["sub"]),
             Spacer(1, 18), t, Spacer(1, 14),
             Paragraph("This receipt was generated by SecureBank after the transfer was confirmed "
                       "with the hardware token.", st["sub"])]
    return pdf_response(story, f"receipt-{r['ref']}.pdf", "Transfer receipt")


def esc(v):
    from xml.sax.saxutils import escape
    return escape(str(v))


# ------------------------------------------------------- statement PDF
@app.route("/history.pdf")
@login_required
def history_pdf():
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    kind = request.args.get("type", "all")
    q = request.args.get("q", "").strip()
    d_from, d_to = clean_day(request.args.get("from")), clean_day(request.args.get("to"))
    sql, args = history_query(g.user["account"], kind, q, d_from, d_to)
    rows = get_db().execute("SELECT * " + sql + " ORDER BY ts DESC, id DESC LIMIT 5000", args).fetchall()
    st = pdf_styles()
    filt = []
    if kind in ("credit", "debit"):
        filt.append("Money in" if kind == "credit" else "Money out")
    if q:
        filt.append(f'Search: "{q}"')
    if d_from or d_to:
        filt.append(f"Dates: {d_from or 'start'} to {d_to or 'today'}")
    data = [["Date", "Description", "Amount (Rs.)", "Balance (Rs.)"]]
    for r in rows:
        data.append([dt(r["ts"]), Paragraph(esc(r["description"]), st["cell"]),
                     f"{r['amount']:,.2f}", f"{r['balance_after']:,.2f}"])
    if len(data) == 1:
        data.append(["", "No transactions found.", "", ""])
    t = Table(data, colWidths=[95, 255, 80, 85], repeatRows=1)
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5), ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), "#142B4A"), ("TEXTCOLOR", (0, 0), (-1, 0), "#FFFFFF"),
        ("ALIGN", (2, 0), (3, -1), "RIGHT"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 1), (-1, -1), .4, "#E3E9F2"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story = [Paragraph("SecureBank", st["h"]),
             Paragraph(f"Account statement &middot; {esc(g.user['name'])} &middot; {g.user['account']}", st["sub"]),
             Paragraph("Generated " + dt(time.time()) + (" &middot; " + esc("; ".join(filt)) if filt else ""),
                       st["sub"]), Spacer(1, 14), t]
    return pdf_response(story, "statement.pdf", "Account statement")


# ------------------------------------------------------------- payees
@app.route("/payees", methods=["GET", "POST"])
@login_required
def beneficiaries():
    d, acct = get_db(), g.user["account"]
    error = None
    if request.method == "POST":
        nick = request.form.get("nickname", "").strip()
        to = request.form.get("to", "").strip()
        count = d.execute("SELECT COUNT(*) FROM beneficiaries WHERE account=?", (acct,)).fetchone()[0]
        if not (1 <= len(nick) <= 30):
            error = "Enter a nickname of up to 30 characters."
        elif not (to.isdigit() and 6 <= len(to) <= 14):
            error = "Enter a valid account number (6-14 digits)."
        elif to == acct:
            error = "You cannot save your own account as a payee."
        elif count >= MAX_PAYEES:
            error = f"You can save up to {MAX_PAYEES} payees. Remove one first."
        else:
            try:
                d.execute("INSERT INTO beneficiaries(account,nickname,to_account,created_ts) VALUES(?,?,?,?)",
                          (acct, nick, to, int(time.time())))
                d.commit()
            except sqlite3.IntegrityError:
                error = "That account is already in your payees."
            else:
                audit(acct, "payee_added", to)
                flash(f"Saved {nick} as a payee.")
                return redirect(url_for("beneficiaries"))
    rows = d.execute("SELECT * FROM beneficiaries WHERE account=? ORDER BY nickname COLLATE NOCASE",
                     (acct,)).fetchall()
    payees = []
    for b in rows:
        status, wait = recipient_status(acct, b["to_account"])
        payees.append({"id": b["id"], "nickname": b["nickname"], "to": b["to_account"],
                       "ready": status == "trusted", "minutes": -(-wait // 60)})
    return render_template("beneficiaries.html", payees=payees, error=error,
                           new_limit=NEW_RECIPIENT_LIMIT, new_delay=NEW_RECIPIENT_DELAY // 60)


@app.route("/payees/<int:bid>/delete", methods=["POST"])
@login_required
def beneficiary_delete(bid):
    d = get_db()
    b = d.execute("SELECT * FROM beneficiaries WHERE id=? AND account=?", (bid, g.user["account"])).fetchone()
    if b:
        d.execute("DELETE FROM beneficiaries WHERE id=?", (bid,))
        d.commit()
        audit(g.user["account"], "payee_removed", b["to_account"])
        flash(f"Removed {b['nickname']} from your payees.")
    return redirect(url_for("beneficiaries"))


# ----------------------------------------------------- change password
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    acct, error = g.user["account"], None
    if request.method == "POST":
        cur = request.form.get("current", "")
        new = request.form.get("new", "")
        conf = request.form.get("confirm", "")
        code = request.form.get("otp", "").strip()
        if is_locked(acct):
            error = "Too many attempts. Try again in a minute."
        elif len(new) < 8 or not any(c.isalpha() for c in new) or not any(c.isdigit() for c in new):
            error = "New password must be at least 8 characters and include a letter and a number."
        elif new != conf:
            error = "New password and confirmation do not match."
        elif new == cur:
            error = "New password must be different from your current password."
        elif not check_password_hash(g.user["pw_hash"], cur):
            register_fail(acct)
            audit(acct, "password_change_fail", "wrong current password")
            error = "Current password is incorrect."
        else:
            ok, why = check_code(g.user["device_id"], code)
            if ok:
                get_db().execute("UPDATE users SET pw_hash=? WHERE account=?",
                                 (generate_password_hash(new), acct))
                get_db().commit()
                audit(acct, "password_changed")
                flash("Password changed. Use your new password next time you sign in.")
                return redirect(url_for("security"))
            register_fail(acct)
            audit(acct, "otp_fail", why + " (password change)")
            error = why
    return render_template("change_password.html", error=error, device=g.user["device_id"])


@app.route("/session/ping", methods=["POST"])
@login_required
def session_ping():
    """Keeps a signed-in session alive (refreshes the session cookie)."""
    return jsonify(ok=True)


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
    return jsonify(done=False)


if __name__ == "__main__":
    import socket

    def is_port_free(p):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("127.0.0.1", p)) != 0

    port = int(os.environ.get("PORT", 5000 if is_port_free(5000) else 5001))
    # 0.0.0.0 so the ESP32 on the same Wi-Fi can reach the server
    print(f" * Running SecureBank on http://127.0.0.1:{port} (host 0.0.0.0)")
    app.run(host="0.0.0.0", port=port, debug=False)
