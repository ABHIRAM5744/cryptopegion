#!/usr/bin/env python3
"""CryptoPegion end-to-end test suite.

Covers: core zero-knowledge API (create/open/burn/expiry/meta), Free-plan
caps (TTL, payload size, monthly transfer budget), accounts & auth (signup /
login / logout / CSRF), demo plan upgrades (Ultimate: ads off, branding on,
bigger caps), the ads income engine (impressions / clicks / paid-viewer
suppression) and the admin panel.

Run against a fresh server:
    DB_PATH=/tmp/cp_e2e.db PORT=5000 python app.py &   # demo mode default
    python test_e2e.py
"""
import base64
import http.cookiejar
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("TEST_BASE", "http://127.0.0.1:5000")
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cryptopegion.db"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@cryptopegion.local")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "demo-admin-123")

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), "-", name, ((" [" + detail + "]") if detail else ""))


def opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", "cp-e2e")]
    return op


def _read(resp):
    raw = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except Exception:
        return raw


def raw(op, method, path, data=None, ctype=None):
    req = urllib.request.Request(BASE + path, method=method)
    body = None
    if data is not None:
        if ctype == "json":
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        else:
            body = urllib.parse.urlencode(data).encode()
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with op.open(req, body) as r:
            return r.status, _read(r), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, _read(e), e.geturl()


def jsonget(op, path):
    s, d, _ = raw(op, "GET", path, None, "json")
    return s, d


def jsonpost(op, path, payload):
    return raw(op, "POST", path, payload, "json")


def formpost(op, path, fields):
    return raw(op, "POST", path, fields, None)


def csrf_of(html):
    if not isinstance(html, str):
        return None
    m = re.search(r'<meta name="csrf" content="([^"]+)"', html)
    return m.group(1) if m else None


def page_has(op, path, needle):
    s, body, _ = raw(op, "GET", path)
    return s == 200 and isinstance(body, str) and needle in body


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=()):
    with db() as c:
        return c.execute(sql, args).fetchall()


def q1(sql, args=()):
    rows = q(sql, args)
    return dict(rows[0]) if rows else None


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
FAKE_CT = base64.b64encode(b"x" * 64).decode()
IV = base64.b64encode(b"0" * 12).decode()
BIG_CT = base64.b64encode(b"y" * (11 * 1024 * 1024)).decode()  # > 10 MB Free cap


def make_note(op, max_views=1, ttl_minutes=None, has_file=False, extra=None):
    body = {"ct": FAKE_CT, "iv": IV, "max_views": max_views, "has_file": has_file}
    if ttl_minutes is not None:
        body["ttl_minutes"] = ttl_minutes
    body.update(extra or {})
    s, d, _ = jsonpost(op, "/api/notes", body)
    return s, d


def signup(op, email, name="Test User", pw="password123"):
    return formpost(op, "/signup", {"name": name, "email": email,
                                    "password": pw, "csrf_token": csrf_of(op and _fetch_login_csrf(op))})


def _fetch_login_csrf(op):
    s, body, _ = raw(op, "GET", "/login")
    tok = csrf_of(body) if isinstance(body, str) else None
    return tok or ""


def login(op, email, pw):
    return formpost(op, "/login", {"email": email, "password": pw,
                                   "csrf_token": _fetch_login_csrf(op)})


# --------------------------------------------------------------------------- #
# 1. Anonymous core zero-knowledge API
# --------------------------------------------------------------------------- #
anon = opener()

s, d = make_note(anon, max_views=3, ttl_minutes=60)
nid = d.get("id", "") if isinstance(d, dict) else ""
check("create 3-view note (anon)", s == 201 and nid, f"status={s}")

s, d = jsonget(anon, f"/api/notes/{nid}/meta")
check("meta pre-check keeps views", s == 200 and d.get("views_left") == 3, str(d)[:120])

s, d, _ = jsonpost(anon, f"/api/notes/{nid}/open", {})
check("open 1/3", s == 200 and d["views_left"] == 2 and not d.get("burned"), str(d)[:120])
s, d, _ = jsonpost(anon, f"/api/notes/{nid}/open", {})
check("open 2/3", s == 200 and d["views_left"] == 1 and not d.get("burned"), str(d)[:120])
s, d, _ = jsonpost(anon, f"/api/notes/{nid}/open", {})
check("open 3/3 burns note", s == 200 and d.get("burned") is True, str(d)[:120])
s, _ = jsonget(anon, f"/api/notes/{nid}/meta")
check("meta after burn -> 404/410", s in (404, 410), f"status={s}")

s, d = make_note(anon, max_views=5, ttl_minutes=1)
nid2 = d.get("id", "")
with db() as c:
    c.execute("UPDATE notes SET expires_at = ? WHERE id = ?", (time.time() - 5, nid2))
s, d, _ = jsonpost(anon, f"/api/notes/{nid2}/open", {})
check("expired note -> 410 expired", s == 410 and isinstance(d, dict) and d.get("error") == "expired", f"status={s}")

s, d = make_note(anon, max_views=5)
nid3 = d.get("id", "")
s, d, _ = jsonpost(anon, f"/api/notes/{nid3}/burn", {})
check("manual burn endpoint", s == 200 and isinstance(d, dict) and d.get("burned") is True, f"status={s}")

s, _ = make_note(anon, max_views=5000)
check("max_views=5000 rejected", s == 400, f"status={s}")
s, _, _ = jsonpost(anon, "/api/notes", {"ct": FAKE_CT, "iv": base64.b64encode(b"0" * 11).decode()})
check("bad IV length rejected", s == 400, f"status={s}")
s, d = make_note(anon, max_views=1, has_file=True)
nid4 = d.get("id", "")
s, d, _ = jsonpost(anon, f"/api/notes/{nid4}/open", {})
check("has_file round-trip (legacy defaults file_count=1)",
      s == 200 and isinstance(d, dict) and d.get("has_file") is True
      and d.get("file_count") == 1, str(d)[:120])

# Receiver page renders for a live note
s, d = make_note(anon, max_views=1, ttl_minutes=5)
nid5 = d.get("id", "")
s, body, _ = raw(anon, "GET", f"/note/{nid5}")
check("receiver page 200 + brand-free copy",
      s == 200 and isinstance(body, str) and "received something secure" in body, f"status={s}")

# Multi-file metadata: file_count round-trips on create/meta/open, pure text
# notes are 0 files, and out-of-range counts are rejected without creating.
s, d = make_note(anon, max_views=1, extra={"file_count": 3})
nid5f = d.get("id", "")
s, d = jsonget(anon, f"/api/notes/{nid5f}/meta")
check("meta reports file_count=3", s == 200 and d.get("file_count") == 3
      and d.get("has_file") is True, f"status={s} {str(d)[:120]}")
s, d, _ = jsonpost(anon, f"/api/notes/{nid5f}/open", {})
check("open reports file_count=3",
      s == 200 and d.get("file_count") == 3 and d.get("has_file") is True, str(d)[:120])

s, d = make_note(anon, max_views=1, extra={"file_count": 0})
nid5p = d.get("id", "")
s, d = jsonget(anon, f"/api/notes/{nid5p}/meta")
check("pure text note has file_count=0",
      s == 200 and d.get("file_count") == 0 and d.get("has_file") is False, f"status={s} {str(d)[:120]}")

for bad in (51, -3, "abc"):
    s, d = make_note(anon, max_views=1, extra={"file_count": bad})
    check(f"file_count={bad!r} rejected", s == 400, f"status={s}")

# 2. Ads income engine — guest impressions & clicks
before = sum(r["impressions"] for r in q("SELECT impressions FROM ads WHERE slot='top_banner' AND active=1"))
for _ in range(2):
    s, d = jsonget(anon, "/api/ads?slot=top_banner")
    check("guest gets an ad", s == 200 and isinstance(d, dict) and d.get("enabled") and d.get("ad"), str(d)[:120])
    ad_id = d["ad"]["id"]
after = sum(r["impressions"] for r in q("SELECT impressions FROM ads WHERE slot='top_banner' AND active=1"))
check("impressions incremented by 2", after - before == 2, f"{before} -> {after}")

clicks_before = q1("SELECT clicks FROM ads WHERE id = ?", (ad_id,))["clicks"]
s, d, _ = jsonpost(anon, f"/api/ads/{ad_id}/click", {})
clicks_after = q1("SELECT clicks FROM ads WHERE id = ?", (ad_id,))["clicks"]
check("ad click counted", s == 200 and clicks_after == clicks_before + 1, f"status={s}")
s, _ = jsonget(anon, "/api/ads?slot=bogus")
check("unknown ad slot rejected", s == 400, f"status={s}")

# Free-plan TTL & payload caps (anonymous = free tier)
s, d = make_note(anon, max_views=1, ttl_minutes=4321)
check("anon free ttl > 3 days rejected", s == 400, f"status={s}")
s, d, _ = jsonpost(anon, "/api/notes", {"ct": BIG_CT, "iv": IV})
check("anon payload > 10 MB rejected", s == 413, f"status={s}")

# Free-plan transfer budget: 10 / month, 11th is 429 (fresh anonymous browser)
anon_caps = opener()
raw(anon_caps, "GET", "/")  # warm: first response sets the cp_anon cookie
ok_budget = True
for i in range(10):
    s, _ = make_note(anon_caps, max_views=1)
    if s != 201:
        ok_budget = False
        break
s, d = make_note(anon_caps, max_views=1)
check("anon free budget: 10 ok then 11th -> 429",
      ok_budget and s == 429 and isinstance(d, dict) and "10 transfers" in d.get("error", ""),
      f"status={s} detail={str(d)[:100]}")

# 3. Accounts, sign-in and plan upgrades
u1 = opener()
s, body, url = raw(u1, "GET", "/signup")
check("signup page 200", s == 200 and "Create your account" in (body if isinstance(body, str) else ""), f"status={s}")

tok = csrf_of(body)
s, body, _ = raw(u1, "POST", "/signup", {"name": "X", "email": "not-an-email",
                                         "password": "short", "csrf_token": tok}, None)
check("signup validation blocks bad input", s == 200 and isinstance(body, str) and "valid email" in body, f"status={s}")

s, body, url = raw(u1, "POST", "/signup",
                   {"name": "Free Tester", "email": "free@example.com",
                    "password": "password123", "csrf_token": tok}, None)
check("signup succeeds (redirect to dashboard)",
      s == 200 and isinstance(body, str) and "Hey," in body and "free" in body.lower(), f"status={s} url={url}")

s, d = jsonget(u1, "/api/me")
check("/api/me free authed", s == 200 and d.get("authed") and d.get("plan") == "free" and d.get("ads") is True, str(d)[:140])
s, d = jsonget(u1, "/api/ads?slot=top_banner")
check("free (signed-in) user sees ads", s == 200 and isinstance(d, dict) and d.get("enabled"), str(d)[:100])

# CSRF protection on state-changing form routes
s, body, _ = raw(u1, "POST", "/account/upgrade", {"plan": "ultimate"})
check("upgrade without csrf -> 400", s == 400, f"status={s}")

s, body, _ = raw(u1, "GET", "/account")
tok = csrf_of(body)
s, body, url = raw(u1, "POST", "/account/upgrade", {"plan": "ultimate", "csrf_token": tok}, None)
check("demo upgrade to Ultimate works",
      s == 200 and isinstance(body, str) and "ultimate" in body.lower(), f"status={s}")

s, d = jsonget(u1, "/api/me")
check("ultimate: ads off, branding on, 64 MB, ttl 43200",
      s == 200 and d.get("plan") == "ultimate" and d.get("ads") is False
      and d["limits"]["branding"] is True and d["limits"]["payload_mb"] == 64
      and d["limits"]["ttl_max_min"] == 43200, str(d)[:160])
s, d = jsonget(u1, "/api/ads?slot=top_banner")
check("paid user: /api/ads suppressed", s == 200 and isinstance(d, dict) and d.get("enabled") is False, str(d)[:100])

# Branding round-trip as Ultimate
s, d = make_note(u1, max_views=2, ttl_minutes=10000,
                 extra={"brand_name": "Acme Studio", "brand_color": "#123456"})
nid6 = d.get("id", "")
check("ultimate creates 30d-range branded note", s == 201 and nid6, f"status={s}")
s, d = jsonget(u1, f"/api/notes/{nid6}/meta")
check("brand appears in meta", s == 200 and d.get("brand_name") == "Acme Studio"
      and d.get("brand_color") == "#123456", str(d)[:140])
s, body, _ = raw(u1, "GET", f"/note/{nid6}")
check("receiver page shows brand", s == 200 and isinstance(body, str) and "Acme Studio" in body, f"status={s}")
s, d, _ = jsonpost(u1, f"/api/notes/{nid6}/open", {})
check("brand returns on open", s == 200 and d.get("brand_name") == "Acme Studio", str(d)[:140])
s, _, _ = jsonpost(u1, f"/api/notes/{nid6}/burn", {})
check("paid burn ok", s == 200, f"status={s}")

# Free user gets no branding, even if payload lies
free2 = opener()
s, body, _ = raw(free2, "POST", "/signup",
                 {"name": "No Brand", "email": "nobrand@example.com",
                  "password": "password123", "csrf_token": _fetch_login_csrf(free2)}, None)
s, d = make_note(free2, max_views=1, extra={"brand_name": "HACK", "brand_color": "#ff0000"})
nid7 = d.get("id", "")
s, d = jsonget(free2, f"/api/notes/{nid7}/meta")
check("free user branding stripped server-side",
      s == 200 and d.get("brand_name") is None and d.get("brand_color") is None, str(d)[:140])

# Login / logout correctness
wrong = opener()
s, body, _ = login(wrong, "free@example.com", "not-the-password")
check("wrong password rejected", s == 200 and isinstance(body, str) and "Wrong email or password" in body, f"status={s}")
l = opener()
s, body, _ = login(l, "free@example.com", "password123")
check("correct sign-in works", s == 200 and isinstance(body, str) and "Hey," in body, f"status={s}")
s, body, _ = raw(l, "GET", "/account")
tok = csrf_of(body)
s, body, _ = raw(l, "POST", "/logout", {"csrf_token": tok}, None)
check("logout lands on home", s == 200 and isinstance(body, str) and "Send anything" in body, f"status={s}")
s, d = jsonget(l, "/api/me")
check("me after logout is anon", s == 200 and d.get("authed") is False, str(d)[:80])

# Normal user cannot reach admin
s, d = jsonget(u1, "/admin")
check("non-admin blocked from /admin", s == 403, f"status={s}")

# 3b. Multi-file usage counters for accounts
fu = opener()
s, body, _ = raw(fu, "POST", "/signup",
                 {"name": "File User", "email": "files@example.com",
                  "password": "password123", "csrf_token": _fetch_login_csrf(fu)}, None)
s, d = jsonget(fu, "/api/me")
usage0 = (d.get("usage") or {}) if isinstance(d, dict) else {}
check("files user starts at zero usage",
      s == 200 and d.get("plan") == "free" and usage0.get("transfers") == 0
      and usage0.get("files") == 0, f"status={s} {str(d)[:160]}")

s, d = make_note(fu, max_views=2, extra={"file_count": 2})
nidF2 = d.get("id", "")
s, d = make_note(fu, max_views=1, extra={"file_count": 3})
nidF3 = d.get("id", "")
s, d = jsonget(fu, "/api/me")
u = (d.get("usage") or {}) if isinstance(d, dict) else {}
check("usage counts 2 transfers / 5 files",
      bool(nidF2 and nidF3) and u.get("transfers") == 2 and u.get("files") == 5,
      f"status={s} usage={u}")

s, d = jsonget(fu, "/api/me/notes")
byid = {n["id"]: n for n in d.get("notes", [])} if isinstance(d, dict) else {}
check("/api/me/notes exposes file_count",
      s == 200 and byid.get(nidF2, {}).get("file_count") == 2
      and byid.get(nidF3, {}).get("file_count") == 3, f"status={s}")

s, body, _ = raw(fu, "GET", "/account")
check("account page shows file stats + per-note counts",
      s == 200 and isinstance(body, str) and "Files this month" in body
      and "2 files" in body and "3 files" in body, f"status={s}")

# 3c. Demo billing lifecycle (server defaults to DEMO_MODE=1, no Stripe)
buy = opener()
s, body, _ = raw(buy, "POST", "/signup",
                 {"name": "Bill Buyer", "email": "bill@example.com",
                  "password": "password123", "csrf_token": _fetch_login_csrf(buy)}, None)
s, d = jsonget(buy, "/api/me")
check("buyer starts free", s == 200 and d.get("plan") == "free", f"status={s} {str(d)[:120]}")

s, body, _ = raw(buy, "GET", "/account")
tok = csrf_of(body)
s, body, url = raw(buy, "POST", "/account/upgrade",
                   {"plan": "ultimate", "csrf_token": tok}, None)
s, d = jsonget(buy, "/api/me")
check("demo upgrade activates instantly",
      s == 200 and d.get("plan") == "ultimate", f"status={s} plan={d.get('plan')}")

s, body, _ = raw(buy, "GET", "/account")
check("paid account copy shows demo billing state",
      s == 200 and isinstance(body, str) and "activated without a payment" in body
      and "switch to Free" in body and "no card on file" in body, f"status={s}")

tok = csrf_of(body)
s, body, url = raw(buy, "POST", "/account/upgrade",
                   {"plan": "free", "csrf_token": tok}, None)
s, d = jsonget(buy, "/api/me")
check("downgrade back to free works", s == 200 and d.get("plan") == "free", f"plan={d.get('plan')}")

s, body, _ = raw(buy, "GET", "/account")
check("free account copy shows demo footnote + upgrade CTA",
      s == 200 and isinstance(body, str) and "no payment is collected" in body
      and "Try Ultimate" in body, f"status={s}")

s, body, _ = raw(u1, "GET", "/account")
check("existing ultimate user sees demo billing state",
      s == 200 and isinstance(body, str) and "activated without a payment" in body
      and "switch to Free" in body and "no card on file" in body, f"status={s}")

s, body, url = raw(buy, "GET", "/account/upgrade/cancel")
check("upgrade cancel -> pricing?canceled=1 banner",
      s == 200 and "canceled=1" in url and isinstance(body, str)
      and "Checkout was canceled" in body, f"status={s} url={url}")

s, body, url = raw(buy, "GET", "/account/upgrade/success")
check("upgrade success w/o session -> upgrade=missing",
      s == 200 and "upgrade=missing" in url and isinstance(body, str)
      and "No checkout session was provided" in body, f"url={url}")

s, d, _ = jsonpost(buy, "/api/stripe/webhook", {})
check("stripe webhook unconfigured -> 400",
      s == 400 and "not configured" in str(d), f"status={s} {str(d)[:120]}")

# 4. Admin panel (seeded demo admin)
adm = opener()
s, body, _ = login(adm, ADMIN_EMAIL, ADMIN_PASSWORD)
check("demo admin signs in", s == 200 and isinstance(body, str) and "Hey," in body, f"status={s}")
s, body, _ = raw(adm, "GET", "/admin")
check("admin panel renders ads + users",
      s == 200 and isinstance(body, str) and "Ad manager" in body and "Ad unit" in body
      and "free@example.com" in body, f"status={s}")

tok = csrf_of(body)
s, body, _ = raw(adm, "POST", "/admin/ads",
                 {"name": "E2E test ad", "slot": "composer", "url": "https://example.com",
                  "cpm": "3.5", "code": '<a class="demo-ad" href="https://example.com"><b>Sponsored</b> E2E</a>',
                  "csrf_token": tok}, None)
row = q1("SELECT id, slot, cpm, active FROM ads WHERE name = 'E2E test ad'")
check("admin can add an ad unit", s == 200 and row and row["slot"] == "composer" and row["cpm"] == 3.5, f"status={s}")
if row:
    e2e_ad = row["id"]
    s, body, _ = raw(adm, "POST", f"/admin/ads/{e2e_ad}/delete", {"csrf_token": tok}, None)
    check("admin can delete an ad unit", s == 200 and not q1("SELECT id FROM ads WHERE id = ?", (e2e_ad,)), f"status={s}")

# Admin can edit another user's plan
uid_row = q1("SELECT id FROM users WHERE email = 'free@example.com'")
s, body, _ = raw(adm, "POST", f"/admin/users/{uid_row['id']}/save",
                 {"plan": "ultimate", "csrf_token": tok}, None)
check("admin edits user plan", s == 200 and q1("SELECT plan FROM users WHERE id = ?", (uid_row['id'],))["plan"] == "ultimate", f"status={s}")

print()
fails = [r for r in results if not r[1]]
print(f"{len(results) - len(fails)}/{len(results)} checks passed")
raise SystemExit(1 if fails else 0)
