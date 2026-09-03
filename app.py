#!/usr/bin/env python3
"""
CryptoPegion — encrypted, self-destructing transfers (notes & files).

Product model (WeTransfer-style):
  * Free       — $0,  10 transfers/month, ~3 GB/month, expiry up to 3 days, ad-supported.
  * Ultimate   — $23/mo billed monthly, no usage caps, custom branding, ad-free.
  * Teams      — $19/user/mo (min 2), everything in Ultimate for a team.

Zero-knowledge core (unchanged promise):
  - The browser generates a random AES-256 key and encrypts the note/file
    BEFORE anything is sent to the server.
  - The key lives ONLY in the URL fragment (after #), which browsers never
    send to servers. The server stores only ciphertext and metadata.
  - After the view limit is reached (or TTL expires) the row is deleted.

Monetization / ads:
  - Free-tier senders and anonymous visitors see ads (slots: top banner,
    composer, receiver page). Paid plans are ad-free.
  - Ad units are stored in the DB and managed from /admin (impressions,
    clicks, CPM and estimated revenue are tracked). AdSense or any ad HTML
    can be pasted into a unit; built-in demo units ship by default.

Run:  pip install -r requirements.txt
      python app.py            ->  http://localhost:5000
"""

import base64
import json
import os
import re
import secrets
import sqlite3
import time

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Optional .env for deployment secrets (Stripe keys, price ids, webhook secret).
# Existing environment variables always win (override=False).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    pass

DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "cryptopegion.db"))
DATA_DIR = os.path.dirname(os.path.abspath(DB_PATH)) or BASE_DIR

ENABLE_ADS = os.environ.get("ENABLE_ADS", "1") == "1"
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"   # demo upgrades w/o payment
MAX_BODY_MB = int(os.environ.get("MAX_BODY_MB", "160"))  # request body cap

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@cryptopegion.local")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "demo-admin-123")
ANON_COOKIE = "cp_anon"
BRAND_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# --- Real billing (Stripe) ------------------------------------------------ #
# Upgrades activate the plan only after a successful payment. Set STRIPE_SECRET_KEY
# (and optionally STRIPE_ENABLED=1) plus the monthly price IDs below. When Stripe
# is NOT configured, upgrades fall back to DEMO_MODE (instant switch, no charge)
# so the app stays fully usable offline and by the e2e suite.
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ULTIMATE = os.environ.get("STRIPE_PRICE_ULTIMATE", "")  # monthly price id
STRIPE_PRICE_TEAMS = os.environ.get("STRIPE_PRICE_TEAMS", "")          # per-user price id
STRIPE_ENABLED = bool(STRIPE_SECRET_KEY) or os.environ.get("STRIPE_ENABLED", "0") in ("1", "true", "yes")

MONTH_GB = 3 * 1024 * 1024 * 1024

# Every entitlement used for enforcement lives here.
PLAN_LIMITS = {
    "free": {
        "label": "Free",
        "price": 0,
        "ads": True,
        "branding": False,
        "payload_mb": 10,          # max transfer ~10 MB (demo-friendly; tune w/ storage)
        "ttl_max_min": 3 * 24 * 60,        # 3 days — "Transfer expiry up to 3 days"
        "transfers_month": 10,             # "10 transfers per month"
        "bytes_month": MONTH_GB,           # "Share and receive up to 3 GB / month"
    },
    "ultimate": {
        "label": "Ultimate",
        "price": 23,               # $23 / month
        "ads": False,
        "branding": True,
        "payload_mb": 64,
        "ttl_max_min": 30 * 24 * 60,       # "Unlimited transfer expiration"
        "transfers_month": None,           # "Unlimited transfers per month"
        "bytes_month": None,               # "No limits on the transfer size"
    },
    "teams": {
        "label": "Teams",
        "price": 19,               # $19 per user / month, min 2 users
        "ads": False,
        "branding": True,
        "payload_mb": 64,
        "ttl_max_min": 30 * 24 * 60,
        "transfers_month": None,
        "bytes_month": None,
    },
}

PLAN_ORDER = ("free", "ultimate", "teams")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_MB * 1024 * 1024


def get_secret_key():
    """Persistent secret next to the DB so sessions survive restarts."""
    key_file = DB_PATH + ".secret"
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    os.makedirs(DATA_DIR, exist_ok=True)
    key = secrets.token_hex(32)
    try:
        with open(key_file, "w", encoding="utf-8") as fh:
            fh.write(key)
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


app.secret_key = get_secret_key()
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 30  # 30 days


def stripe_api():
    """Return the Stripe module when enabled, else None (never crashes)."""
    if not STRIPE_ENABLED:
        return None
    try:
        import stripe
    except ImportError:
        return None
    stripe.api_key = STRIPE_SECRET_KEY
    return stripe


@app.template_filter("ctime")
def jinja_ctime(ts):
    """Render an epoch timestamp as a readable local date/time."""
    if not ts:
        return "\u2014"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL DEFAULT '',
    email      TEXT UNIQUE NOT NULL,
    pw_hash    TEXT NOT NULL,
    plan       TEXT NOT NULL DEFAULT 'free',
    admin      INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    stripe_customer_id TEXT DEFAULT '',
    stripe_sub_id TEXT DEFAULT '',
    stripe_status TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS notes (
    id          TEXT PRIMARY KEY,
    ct          BLOB NOT NULL,
    iv          BLOB NOT NULL,
    has_file    INTEGER NOT NULL DEFAULT 0,
    max_views   INTEGER NOT NULL,
    views_used  INTEGER NOT NULL DEFAULT 0,
    expires_at  REAL,
    owner_type  TEXT,               -- 'user' | 'anon'
    owner_id    TEXT,
    brand_name  TEXT,
    brand_color TEXT,
    file_count  INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_counters (
    owner_type TEXT NOT NULL,
    owner_id   TEXT NOT NULL,
    ym         TEXT NOT NULL,       -- 'YYYY-MM'
    transfers  INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    files      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (owner_type, owner_id, ym)
);
CREATE TABLE IF NOT EXISTS ads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    slot        TEXT NOT NULL,      -- top_banner | composer | receiver
    code        TEXT NOT NULL,      -- trusted admin HTML (AdSense ok)
    url         TEXT NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    impressions INTEGER NOT NULL DEFAULT 0,
    clicks      INTEGER NOT NULL DEFAULT 0,
    cpm         REAL NOT NULL DEFAULT 2.0,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_type, owner_id);
CREATE INDEX IF NOT EXISTS idx_ads_slot_active ON ads(slot, active);
CREATE TABLE IF NOT EXISTS pending_upgrades (
    session_id TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    plan       TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_column(conn, table, column, decl):
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        # Migrate databases created before plans/ads existed.
        ensure_column(conn, "notes", "owner_type", "TEXT")
        ensure_column(conn, "notes", "owner_id", "TEXT")
        ensure_column(conn, "notes", "brand_name", "TEXT")
        ensure_column(conn, "notes", "brand_color", "TEXT")
        ensure_column(conn, "notes", "file_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "notes", "created_at", "REAL NOT NULL DEFAULT 0")
        ensure_column(conn, "users", "stripe_customer_id", "TEXT DEFAULT ''")
        ensure_column(conn, "users", "stripe_sub_id", "TEXT DEFAULT ''")
        ensure_column(conn, "users", "stripe_status", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "usage_counters", "files", "INTEGER NOT NULL DEFAULT 0")
        # ensure pending_upgrades exists on DBs created before billing existed
        conn.execute("CREATE TABLE IF NOT EXISTS pending_upgrades ("
                     "session_id TEXT PRIMARY KEY,"
                     "user_id INTEGER NOT NULL,"
                     "plan TEXT NOT NULL,"
                     "created_at REAL NOT NULL)")

        # Demo admin account (only created on a brand-new DB).
        row = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (name, email, pw_hash, plan, admin, created_at) "
                "VALUES (?, ?, ?, 'ultimate', 1, ?)",
                ("Demo Admin", ADMIN_EMAIL,
                 generate_password_hash(ADMIN_PASSWORD), time.time()),
            )
            print(f"[boot] created demo admin {ADMIN_EMAIL} "
                  f"(password from ADMIN_PASSWORD, default '{ADMIN_PASSWORD}') — "
                  f"change it in production!")

        # Seed demo ad units (income demo). Replace with AdSense units in /admin.
        n = conn.execute("SELECT COUNT(*) AS c FROM ads").fetchone()["c"]
        if n == 0 and ENABLE_ADS:
            now = time.time()
            demo = [
                ("CloudShield VPN — 30% off your first year",
                 "top_banner",
                 '<a class="demo-ad" href="/pricing" target="_blank" rel="noopener">'
                 '<b>Sponsored</b> CloudShield VPN — 30% off your first year. '
                 "Browse safely anywhere.</a>",
                 "/pricing", 2.50),
                ("SecureSend Business — send 50 GB in one go",
                 "top_banner",
                 '<a class="demo-ad" href="/pricing" target="_blank" rel="noopener">'
                 '<b>Sponsored</b> SecureSend Business — send 50 GB in one go, '
                 "zero-knowledge. Free trial.</a>",
                 "/pricing", 2.00),
                ("CryptoPegion Ultimate — no ads, unlimited transfers",
                 "composer",
                 '<a class="demo-ad demo-ad-brand" href="/pricing" '
                 'target="_blank" rel="noopener"><b>Ad</b> CryptoPegion '
                 "<b>Ultimate</b> — remove these ads, unlock custom branding, "
                 "bigger &amp; unlimited transfers. From $23/mo.</a>",
                 "/pricing", 1.50),
                ("NoteVault Pro — encrypted team notes",
                 "receiver",
                 '<a class="demo-ad" href="/pricing" target="_blank" '
                 'rel="noopener"><b>Sponsored</b> NoteVault Pro — end-to-end '
                 "encrypted notes for teams. 14-day free trial.</a>",
                 "/pricing", 1.80),
            ]
            for name, slot, code, url, cpm in demo:
                conn.execute(
                    "INSERT INTO ads (name, slot, code, url, active, cpm, created_at) "
                    "VALUES (?, ?, ?, ?, 1, ?, ?)",
                    (name, slot, code, url, cpm, now),
                )
        # Clear truly dead rows occasionally (cheap sweep).
        conn.execute(
            "DELETE FROM notes WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (time.time() - 60,),
        )


def new_id():
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# Auth / session helpers
# --------------------------------------------------------------------------- #

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT id, name, email, plan, admin, created_at, stripe_customer_id, "
            "stripe_sub_id, stripe_status FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
    if row is None:
        session.clear()
        return None
    return dict(row)


def user_plan(user=None):
    user = user if user is not None else current_user()
    plan = user["plan"] if user else "free"
    return plan if plan in PLAN_LIMITS else "free"


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def csrf_ok():
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    return supplied == session.get("csrf")


def csrf_required(fn):
    def wrapper(*args, **kwargs):
        if not csrf_ok():
            abort(400, description="Invalid or missing CSRF token")
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def admin_required(fn):
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user["admin"]:
            abort(403, description="Admin only")
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def anon_id():
    """Stable per-browser id used for anonymous Free-tier counting."""
    return request.cookies.get(ANON_COOKIE) or ("anon-" + secrets.token_hex(12))


@app.after_request
def ensure_anon_cookie(resp):
    if ANON_COOKIE not in request.cookies and not session.get("uid"):
        resp.set_cookie(ANON_COOKIE, secrets.token_hex(16), max_age=60 * 60 * 24 * 365,
                        httponly=True, samesite="Lax")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.context_processor
def inject_globals():
    return {
        "user": current_user(),
        "csrf_token": csrf_token,
        "DEMO_MODE": DEMO_MODE,
        "ENABLE_ADS": ENABLE_ADS,
        "STRIPE_ENABLED": STRIPE_ENABLED,
        "plans": PLAN_LIMITS,
        "plan_order": PLAN_ORDER,
    }


# --------------------------------------------------------------------------- #
# Usage counters (Free-tier enforcement)
# --------------------------------------------------------------------------- #

def plan_limits(plan=None):
    return PLAN_LIMITS.get(plan or user_plan(), PLAN_LIMITS["free"])


def usage_row(conn, owner_type, owner_id, ym):
    conn.execute(
        "INSERT OR IGNORE INTO usage_counters (owner_type, owner_id, ym) VALUES (?, ?, ?)",
        (owner_type, owner_id, ym),
    )
    return conn.execute(
        "SELECT transfers, bytes, files FROM usage_counters "
        "WHERE owner_type = ? AND owner_id = ? AND ym = ?",
        (owner_type, owner_id, ym),
    ).fetchone()


def owner_for():
    """Return (owner_type, owner_id) for usage billing of a new transfer."""
    user = current_user()
    if user:
        return "user", str(user["id"])
    return "anon", anon_id()


def enforce_and_charge(owner_type, owner_id, ct_bytes, file_count=0):
    """
    Check the owner's monthly Free-tier budget and charge on success.
    Returns (ok, error_message_or_None). Runs atomically in one transaction.
    """
    if owner_type == "user":
        user = current_user()
        plan = user_plan(user)
    else:
        plan = "free"
    limits = plan_limits(plan)

    ym = time.strftime("%Y-%m")
    with db() as conn:
        row = usage_row(conn, owner_type, owner_id, ym)
        transfers = row["transfers"]
        used_bytes = row["bytes"]
        used_files = row["files"]

        if limits["transfers_month"] is not None and transfers >= limits["transfers_month"]:
            return False, ("Free plan allows 10 transfers per month. "
                           "Upgrade to Ultimate for unlimited transfers.")
        if limits["bytes_month"] is not None and used_bytes + ct_bytes > limits["bytes_month"]:
            return False, ("You have used this month's free 3 GB transfer allowance. "
                           "Upgrade for unlimited transfer size.")
        conn.execute(
            "UPDATE usage_counters SET transfers = transfers + 1, bytes = bytes + ?, "
            "files = files + ? WHERE owner_type = ? AND owner_id = ? AND ym = ?",
            (ct_bytes, file_count, owner_type, owner_id, ym),
        )
    return True, None


def usage_for(owner_type, owner_id):
    ym = time.strftime("%Y-%m")
    with db() as conn:
        row = usage_row(conn, owner_type, owner_id, ym)
    return {"transfers": row["transfers"], "bytes": row["bytes"], "files": row["files"], "month": ym}


def user_notes(user_id):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM notes WHERE owner_type = 'user' AND owner_id = ? "
            "ORDER BY created_at DESC LIMIT 200",
            (str(user_id),),
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return render_template("landing.html", pricing=False)


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/send")
def send_page():
    return render_template("send.html")


@app.route("/note/<note_id>")
def note_page(note_id):
    brand_name = brand_color = None
    with db() as conn:
        row = conn.execute(
            "SELECT brand_name, brand_color FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    if row is not None and row["brand_name"]:
        brand_name = row["brand_name"]
        brand_color = row["brand_color"] or None
    return render_template(
        "note.html", note_id=note_id, brand_name=brand_name, brand_color=brand_color
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("uid"):
        return redirect(url_for("account"))
    error = None
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()[:80]
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        if not csrf_ok():
            error = "Session expired — please try again."
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            error = "Please enter a valid email address."
        elif len(pw) < 8:
            error = "Password must be at least 8 characters."
        elif not name:
            error = "Please enter your name."
        else:
            with db() as conn:
                try:
                    cur = conn.execute(
                        "INSERT INTO users (name, email, pw_hash, plan, created_at) "
                        "VALUES (?, ?, ?, 'free', ?)",
                        (name, email, generate_password_hash(pw), time.time()),
                    )
                except sqlite3.IntegrityError:
                    error = "That email is already registered — try signing in."
                else:
                    session.clear()
                    session["uid"] = cur.lastrowid
                    return redirect(request.args.get("next") or url_for("account"))
    return render_template("signup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("account"))
    error = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        if not csrf_ok():
            error = "Session expired — please try again."
        else:
            with db() as conn:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row is None or not check_password_hash(row["pw_hash"], pw):
                error = "Wrong email or password."
            else:
                session.clear()
                session["uid"] = row["id"]
                return redirect(request.args.get("next") or url_for("account"))
    return render_template("login.html", error=error)


@app.post("/logout")
@csrf_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/account")
@login_required
def account():
    user = current_user()
    notes = user_notes(user["id"])
    usage = usage_for("user", str(user["id"]))
    limits = plan_limits(user["plan"])
    now = time.time()
    for n in notes:
        n["views_left"] = max(0, n["max_views"] - n["views_used"])
        if n["expires_at"]:
            n["ttl_left_sec"] = max(0, int(n["expires_at"] - now))
    return render_template("account.html", notes=notes, usage=usage, limits=limits)


# --------------------------------------------------------------------------- #
# Billing (Stripe Checkout subscriptions)
# --------------------------------------------------------------------------- #
# Upgrade flow: /pricing form -> POST /account/upgrade -> Stripe Checkout page
# -> /account/upgrade/success (only after a successful payment) -> plan active.
# The /api/stripe/webhook endpoint is the ongoing source of truth for the
# subscription lifecycle (renewals, cancellations, failed payments). When
# Stripe is not configured, DEMO_MODE instantly switches the plan so the app
# and the e2e suite stay fully usable without credentials.

PAID_PLANS = ("ultimate", "teams")


def set_user_plan(user_id, plan, customer_id="", sub_id="", status=""):
    """Persist a plan/Stripe change. Idempotent, safe to call twice."""
    with db() as conn:
        conn.execute(
            "UPDATE users SET plan = ?, stripe_customer_id = ?, stripe_sub_id = ?, "
            "stripe_status = ? WHERE id = ?",
            (plan, customer_id, sub_id, status, user_id),
        )


def stripe_price_for(plan):
    return {"ultimate": STRIPE_PRICE_ULTIMATE,
            "teams": STRIPE_PRICE_TEAMS}.get(plan, "")


def create_checkout_session(user, plan):
    """Create a Stripe Checkout Session for a monthly subscription."""
    price = stripe_price_for(plan)
    if not price:
        abort(502, description=f"No Stripe price id configured for the {plan} plan "
                               f"(set STRIPE_PRICE_{plan.upper()})")
    stripe = stripe_api()
    if stripe is None:
        abort(502, description="Stripe is not configured on this server")
    meta = {"user_id": str(user["id"]), "plan": plan}
    try:
        sess = stripe.checkout.Session.create(
            mode="subscription",
            customer=user.get("stripe_customer_id") or None,
            customer_email=(None if user.get("stripe_customer_id")
                            else user["email"]),
            client_reference_id=str(user["id"]),
            line_items=[{"price": price, "quantity": 1}],
            metadata=meta,
            subscription_data={"metadata": meta},
            allow_promotion_codes=True,
            success_url=url_for("account_upgrade_success", _external=True)
            + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("account_upgrade_cancel", _external=True),
        )
    except Exception as exc:  # network, bad key, or invalid price id
        app.logger.warning("stripe checkout create failed: %s", exc)
        abort(502, description="Could not reach Stripe. Check STRIPE_SECRET_KEY "
                               "and the price ids, then try again.")
    with db() as conn:
        conn.execute(
            "INSERT INTO pending_upgrades (session_id, user_id, plan, created_at) "
            "VALUES (?, ?, ?, ?)",
            (sess.id, user["id"], plan, time.time()),
        )
    return sess


@app.post("/account/upgrade")
@login_required
@csrf_required
def account_upgrade():
    """Start or stop a paid plan. Paid plans activate only after payment."""
    plan = request.form.get("plan", "free")
    if plan not in PLAN_LIMITS:
        abort(400, description="Unknown plan")
    user = current_user()

    if plan == "free":
        # Downgrade: cancel any live Stripe subscription, then drop to Free.
        sub_id = user.get("stripe_sub_id") or ""
        if sub_id:
            stripe = stripe_api()
            if stripe is not None:
                try:
                    stripe.subscription.cancel(sub_id)
                except Exception as exc:
                    app.logger.warning("stripe cancel failed: %s", exc)
        set_user_plan(user["id"], "free",
                      user.get("stripe_customer_id") or "", "", "canceled")
        return redirect(url_for("account"))

    if STRIPE_ENABLED:
        sess = create_checkout_session(user, plan)
        return redirect(sess.url)  # hosted Stripe Checkout page

    if DEMO_MODE:
        # Offline fallback used by the demo and the e2e suite: no charge.
        set_user_plan(user["id"], plan)
        return redirect(url_for("account"))

    abort(403, description="Real payments are not enabled on this build "
                           "(set STRIPE_SECRET_KEY or DEMO_MODE=1)")


@app.get("/account/upgrade/success")
@login_required
def account_upgrade_success():
    """Landing page after Stripe Checkout — activates the plan once paid."""
    user = current_user()
    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return redirect(url_for("account", upgrade="missing"))

    # Consume the pending record started at checkout time (the webhook may
    # have already done this; that is fine — the row is deleted idempotently).
    pending = None
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM pending_upgrades WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is not None:
            conn.execute("DELETE FROM pending_upgrades WHERE session_id = ?",
                         (session_id,))
            pending = dict(row)

    stripe = stripe_api()
    if stripe is None:
        return redirect(url_for("account", upgrade="error"))
    try:
        sess = stripe.checkout.Session.retrieve(session_id)
    except Exception as exc:
        app.logger.warning("stripe session retrieve failed: %s", exc)
        return redirect(url_for("account", upgrade="error"))

    owner_id = sess.get("client_reference_id") or \
        (sess.get("metadata") or {}).get("user_id") or ""
    if str(owner_id) != str(user["id"]):
        return redirect(url_for("account", upgrade="mismatch"))
    if sess.get("payment_status") in ("paid", "no_payment_required"):
        plan = (pending or {}).get("plan") or \
            (sess.get("metadata") or {}).get("plan") or "ultimate"
        if plan not in PAID_PLANS:
            plan = "ultimate"
        set_user_plan(user["id"], plan,
                      sess.get("customer") or "",
                      sess.get("subscription") or "", "active")
        return redirect(url_for("account", upgraded=1))
    # Invoice not settled yet (rare with cards) — the webhook will catch it.
    return redirect(url_for("account", upgrade="pending"))


@app.get("/account/upgrade/cancel")
@login_required
def account_upgrade_cancel():
    return redirect(url_for("pricing", canceled=1))


@app.post("/api/stripe/webhook")
def stripe_webhook():
    """Signature-verified Stripe events: activate and deactivate plans."""
    if not STRIPE_ENABLED or not STRIPE_WEBHOOK_SECRET:
        abort(400, description="Stripe webhook is not configured")
    stripe = stripe_api()
    if stripe is None:
        abort(400, description="Stripe webhook is not configured")
    payload = request.get_data(as_text=True)
    signature = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, signature,
                                               STRIPE_WEBHOOK_SECRET)
        event = event.to_dict()  # stripe>=15 returns an Event object, not a dict
    except Exception:
        abort(400, description="Invalid signature")

    etype = event.get("type")
    obj = event.get("data", {}).get("object", {})
    meta = obj.get("metadata") or {}
    plan = meta.get("plan", "ultimate")
    if plan not in PAID_PLANS:
        plan = "ultimate"

    if etype == "checkout.session.completed":
        # Covers the case where the buyer closed the browser before the
        # success page ran; same idempotent outcome.
        uid = obj.get("client_reference_id") or meta.get("user_id") or ""
        with db() as conn:
            row = conn.execute(
                "SELECT plan FROM pending_upgrades WHERE session_id = ?",
                (obj.get("id"),),
            ).fetchone()
            if row is not None:
                plan = row["plan"]
                conn.execute(
                    "DELETE FROM pending_upgrades WHERE session_id = ?",
                    (obj.get("id"),),
                )
        if not uid:
            return jsonify(received=True, ignored=True)
        set_user_plan(uid, plan, obj.get("customer") or "",
                      obj.get("subscription") or "", "active")
        return jsonify(received=True)

    if etype in ("customer.subscription.updated",
                 "customer.subscription.deleted"):
        customer = obj.get("customer") or ""
        status = obj.get("status") or ""
        if not customer:
            return jsonify(received=True, ignored=True)
        with db() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE stripe_customer_id = ?", (customer,)
            ).fetchone()
        if row is None:
            # Metadata user_id is copied onto the subscription at creation.
            uid = meta.get("user_id") or ""
            if not uid:
                return jsonify(received=True, ignored=True)
            row = {"id": uid}
        if status in ("active", "trialing"):
            set_user_plan(row["id"], plan, customer, obj.get("id") or "", status)
        else:
            # canceled / unpaid / past_due / incomplete_expired -> lose plan.
            set_user_plan(row["id"], "free", customer, "", status)
        return jsonify(received=True)

    return jsonify(received=True)  # acknowledge all other events


@app.post("/account/burn")
@login_required
@csrf_required
def account_burn():
    user = current_user()
    note_id = (request.form.get("note_id") or "").strip()
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM notes WHERE id = ? AND owner_type = 'user' AND owner_id = ?",
            (note_id, str(user["id"])),
        )
    return redirect(url_for("account", burned=1 if cur.rowcount else 0))


# --------------------------------------------------------------------------- #
# Notes API (zero-knowledge core)
# --------------------------------------------------------------------------- #

MAX_VIEWS_LIMIT = 100


@app.route("/api/notes", methods=["POST"])
def create_note():
    data = request.get_json(silent=True) or {}
    try:
        ct = base64.b64decode(data.get("ct", ""), validate=True)
        iv = base64.b64decode(data.get("iv", ""), validate=True)
    except Exception:
        abort(400, description="Invalid ciphertext encoding")

    if not ct or len(iv) != 12:
        abort(400, description="Missing ciphertext or bad IV length")

    owner_type, owner_id = owner_for()
    plan = user_plan() if owner_type == "user" else "free"
    limits = plan_limits(plan)

    if len(ct) > limits["payload_mb"] * 1024 * 1024:
        abort(413, description=f"Payload too large — your {limits['label']} plan "
                               f"allows up to {limits['payload_mb']} MB per transfer")

    try:
        max_views = int(data.get("max_views", 1))
    except (TypeError, ValueError):
        abort(400, description="Invalid max_views")
    if not 1 <= max_views <= MAX_VIEWS_LIMIT:
        abort(400, description=f"max_views must be 1..{MAX_VIEWS_LIMIT}")

    # Optional number of attached files. The file list itself lives inside the
    # ciphertext; only the count travels as metadata.
    try:
        file_count = int(data.get("file_count", 1 if data.get("has_file") else 0))
    except (TypeError, ValueError):
        abort(400, description="Invalid file_count")
    if not 0 <= file_count <= 50:
        abort(400, description="file_count must be 0..50")
    has_file = 1 if (file_count or data.get("has_file")) else 0

    expires_at = None
    ttl = data.get("ttl_minutes")
    if ttl is not None:
        try:
            ttl = int(ttl)
        except (TypeError, ValueError):
            abort(400, description="Invalid ttl_minutes")
        if not 1 <= ttl <= limits["ttl_max_min"]:
            abort(400, description=f"ttl_minutes must be 1..{limits['ttl_max_min']} "
                                   f"on the {limits['label']} plan")
        expires_at = time.time() + ttl * 60

    # Branding is an Ultimate/Teams perk.
    brand_name = brand_color = None
    if limits["branding"]:
        brand_name = (data.get("brand_name") or "").strip()[:60] or None
        brand_color = (data.get("brand_color") or "").strip()
        if brand_color and not BRAND_COLOR_RE.match(brand_color):
            abort(400, description="brand_color must look like #rrggbb")

    # Free-tier monthly budget (10 transfers / 3 GB).
    ok, err = enforce_and_charge(owner_type, owner_id, len(ct), file_count)
    if not ok:
        return jsonify(error=err), 429

    note_id = new_id()
    with db() as conn:
        conn.execute(
            "INSERT INTO notes (id, ct, iv, has_file, max_views, expires_at, "
            "owner_type, owner_id, brand_name, brand_color, file_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (note_id, ct, iv, has_file, max_views, expires_at,
             owner_type, owner_id, brand_name, brand_color, file_count, time.time()),
        )
    return jsonify({"id": note_id, "path": f"/note/{note_id}"}), 201


@app.route("/api/notes/<note_id>/open", methods=["POST"])
def open_note(note_id):
    """
    Atomically consume one view. The row is DELETED the moment the last
    allowed view is used, so even a crash cannot leak it afterwards.
    """
    now = time.time()
    with db() as conn:
        cur = conn.execute(
            "UPDATE notes SET views_used = views_used + 1 "
            "WHERE id = ? AND views_used < max_views "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (note_id, now),
        )
        if cur.rowcount != 1:
            row = conn.execute(
                "SELECT expires_at FROM notes WHERE id = ?", (note_id,)
            ).fetchone()
            if row is None:
                return jsonify(error="gone"), 404
            if row["expires_at"] is not None and row["expires_at"] <= now:
                conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
                return jsonify(error="expired"), 410
            return jsonify(error="exhausted"), 410

        row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        payload = {
            "ct": base64.b64encode(row["ct"]).decode(),
            "iv": base64.b64encode(row["iv"]).decode(),
            "has_file": bool(row["has_file"]),
            "file_count": row["file_count"],
            "views_left": row["max_views"] - row["views_used"],
            "brand_name": row["brand_name"],
            "brand_color": row["brand_color"],
        }
        if row["views_used"] >= row["max_views"]:
            conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            payload["burned"] = True
        return jsonify(payload)


@app.route("/api/notes/<note_id>/meta", methods=["GET"])
def note_meta(note_id):
    """Pre-check WITHOUT consuming a view, so the UI can show status."""
    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT max_views, views_used, expires_at, has_file, file_count, "
            "brand_name, brand_color FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    if row is None:
        return jsonify(exists=False, reason="gone"), 404
    if row["expires_at"] is not None and row["expires_at"] <= now:
        with db() as conn:
            conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        return jsonify(exists=False, reason="expired"), 410
    return jsonify(
        exists=True,
        has_file=bool(row["has_file"]),
        file_count=row["file_count"],
        views_left=row["max_views"] - row["views_used"],
        max_views=row["max_views"],
        expires_at=row["expires_at"],
        brand_name=row["brand_name"],
        brand_color=row["brand_color"],
    )


@app.route("/api/notes/<note_id>/burn", methods=["POST"])
def burn_note(note_id):
    """Allow anyone holding the link to delete now."""
    with db() as conn:
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    if cur.rowcount:
        return jsonify(burned=True)
    return jsonify(burned=False), 404


# --------------------------------------------------------------------------- #
# Account API
# --------------------------------------------------------------------------- #

@app.get("/api/me")
def api_me():
    user = current_user()
    authed = user is not None
    plan = user_plan(user)
    limits = plan_limits(plan)
    out = {
        "authed": authed,
        "plan": plan,
        "ads": bool(ENABLE_ADS and limits["ads"]),
        "demo_mode": DEMO_MODE,
        "limits": {
            "payload_mb": limits["payload_mb"],
            "ttl_max_min": limits["ttl_max_min"],
            "transfers_month": limits["transfers_month"],
            "bytes_month": limits["bytes_month"],
            "branding": limits["branding"],
            "label": limits["label"],
        },
    }
    if authed:
        out["email"] = user["email"]
        out["name"] = user["name"]
        out["admin"] = bool(user["admin"])
        out["usage"] = usage_for("user", str(user["id"]))
    return jsonify(out)


@app.get("/api/me/notes")
def api_my_notes():
    user = current_user()
    if not user:
        return jsonify(error="auth required"), 401
    now = time.time()
    notes = []
    for n in user_notes(user["id"]):
        if n["expires_at"] and n["expires_at"] <= now:
            continue
        notes.append({
            "id": n["id"],
            "has_file": bool(n["has_file"]),
            "file_count": int(n["file_count"] or 0),
            "views_left": n["max_views"] - n["views_used"],
            "max_views": n["max_views"],
            "expires_at": n["expires_at"],
            "created_at": n["created_at"],
            "brand_name": n["brand_name"],
        })
    return jsonify(notes=notes)


# --------------------------------------------------------------------------- #
# Ads API (income engine — shown to Free/guest users only)
# --------------------------------------------------------------------------- #

@app.get("/api/ads")
def api_ad():
    slot = (request.args.get("slot") or "").strip()
    if slot not in ("top_banner", "composer", "receiver"):
        abort(400, description="Unknown ad slot")
    viewer = current_user()
    plan = user_plan(viewer)
    limits = plan_limits(plan)
    if not ENABLE_ADS or limits["ads"] is False:
        return jsonify(enabled=False, ad=None)

    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM ads WHERE slot = ? AND active = 1 ORDER BY RANDOM() LIMIT 1",
            (slot,),
        ).fetchall()
        if not rows:
            return jsonify(enabled=True, ad=None)
        row = rows[0]
        conn.execute("UPDATE ads SET impressions = impressions + 1 WHERE id = ?",
                     (row["id"],))
    return jsonify(enabled=True, ad={
        "id": row["id"],
        "name": row["name"],
        "code": row["code"],
        "url": row["url"],
        "cpm": row["cpm"],
    })


@app.post("/api/ads/<int:ad_id>/click")
def ad_click(ad_id):
    with db() as conn:
        cur = conn.execute("UPDATE ads SET clicks = clicks + 1 WHERE id = ?", (ad_id,))
    if not cur.rowcount:
        return jsonify(ok=False), 404
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
# Admin (ads manager + users)
# --------------------------------------------------------------------------- #

@app.get("/admin")
@admin_required
def admin_panel():
    with db() as conn:
        ads = conn.execute("SELECT * FROM ads ORDER BY slot, id").fetchall()
        users = conn.execute("SELECT id, name, email, plan, admin, created_at "
                             "FROM users ORDER BY id").fetchall()
    ads = [dict(a) for a in ads]
    for a in ads:
        a["revenue"] = a["impressions"] * a["cpm"] / 1000.0
        a["ctr"] = (a["clicks"] / a["impressions"] * 100.0) if a["impressions"] else 0.0
    return render_template("admin.html", ads=ads, users=[dict(u) for u in users])


@app.post("/admin/ads")
@admin_required
@csrf_required
def admin_ad_add():
    name = (request.form.get("name") or "").strip()[:80] or "Untitled ad"
    slot = request.form.get("slot", "top_banner")
    if slot not in ("top_banner", "composer", "receiver"):
        slot = "top_banner"
    code = request.form.get("code") or ""
    url = (request.form.get("url") or "").strip()[:300]
    try:
        cpm = float(request.form.get("cpm") or 0)
    except ValueError:
        cpm = 0.0
    if not code.strip():
        abort(400, description="Ad code/HTML cannot be empty")
    with db() as conn:
        conn.execute(
            "INSERT INTO ads (name, slot, code, url, active, cpm, created_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (name, slot, code, url, cpm, time.time()),
        )
    return redirect(url_for("admin_panel", saved=1))


@app.post("/admin/ads/<int:ad_id>/save")
@admin_required
@csrf_required
def admin_ad_save(ad_id):
    name = (request.form.get("name") or "").strip()[:80] or "Untitled ad"
    slot = request.form.get("slot", "top_banner")
    if slot not in ("top_banner", "composer", "receiver"):
        slot = "top_banner"
    code = request.form.get("code") or ""
    url = (request.form.get("url") or "").strip()[:300]
    active = 1 if request.form.get("active") == "on" else 0
    try:
        cpm = float(request.form.get("cpm") or 0)
    except ValueError:
        cpm = 0.0
    with db() as conn:
        cur = conn.execute(
            "UPDATE ads SET name = ?, slot = ?, code = ?, url = ?, active = ?, "
            "cpm = ? WHERE id = ?",
            (name, slot, code, url, active, cpm, ad_id),
        )
    if not cur.rowcount:
        abort(404)
    return redirect(url_for("admin_panel", saved=1))


@app.post("/admin/ads/<int:ad_id>/delete")
@admin_required
@csrf_required
def admin_ad_delete(ad_id):
    with db() as conn:
        conn.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    return redirect(url_for("admin_panel", saved=1))


@app.post("/admin/users/<int:user_id>/save")
@admin_required
@csrf_required
def admin_user_save(user_id):
    plan = request.form.get("plan", "free")
    if plan not in PLAN_LIMITS:
        abort(400, description="Unknown plan")
    admin = 1 if request.form.get("admin") == "on" else 0
    with db() as conn:
        conn.execute("UPDATE users SET plan = ?, admin = ? WHERE id = ?",
                     (plan, admin, user_id))
    return redirect(url_for("admin_panel", saved=1))


# --------------------------------------------------------------------------- #
# Errors / main
# --------------------------------------------------------------------------- #

@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify(error=e.description), e.code


@app.errorhandler(Exception)
def unhandled_error(e):
    app.logger.exception("unhandled error")
    return jsonify(error="Internal server error"), 500


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
