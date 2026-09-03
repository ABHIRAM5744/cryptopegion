# 🔒 CryptoPegion

Easily send **fully encrypted, secure notes or files with one click**. Just create a note and share the link — the note is deleted from everywhere after the views you allow (or when the timer runs out).

## How it works (zero-knowledge)

```
┌────────────┐   AES-256-GCM in browser    ┌──────────────┐
│  Sender    │ ──── ciphertext only ─────► │ Your server  │
└────────────┘                             └──────────────┘
      │                                            ▲
      ▼  https://yoursite.com/note/abc123#KEY      │
   Share link  (the KEY is in the #fragment —      │
   never sent to the server)  ──── decrypt ────────┘
                                       Receiver
```

- The encryption key lives **only** in the URL `#fragment`, which browsers never transmit.
- The server stores **only ciphertext** — a database breach reveals nothing.
- After the view limit is reached, the row is **deleted in the same atomic request**, so the data is gone from everywhere.
- Optional timer deletes notes even if never opened.

## Features

- 📝 Encrypted notes with a big centered note box
- 📎 **File** ON/OFF toggle — attach a file (drag-and-drop), encrypted together with the note
- ⚙️ **Advanced** ON/OFF toggle:
  - **Views limit** (1–100, default 1) — auto-deletes from everywhere after N opens
  - **Minutes timer** ON/OFF — auto-expire (5 min / 1 hour / 1 day / 7 days / 30 days, plan-dependent)
- 🔥 "Burn now" button to delete immediately
- ⬇️ Receiver gets a clean **Download** button for files
- 🚫 Friendly "this note is gone" screen after burn/expiry
- 👤 **Accounts & plans**: signup/login, Free / Ultimate / Teams with usage caps, one-click (demo) upgrade, admin panel
- 🏷️ **Branding toggle**: Ultimate & Teams can remove the "Powered by CryptoPegion" footer on shared note pages
- 📢 **Ads engine** (free users only): impression + click tracking per ad slot, click-through to advertiser, admin management UI
- 🧪 64 end-to-end API tests + verified browser flow

## Plans

| | **Free** | **Ultimate** | **Teams** |
|---|---|---|---|
| Price | $0 | $23/mo | $19/user/mo (min 2, up to 50) |
| Transfers | 10/mo | Unlimited | Unlimited |
| Data | 3 GB/mo | Unlimited | Unlimited |
| Payload size | 10 MB | 64 MB | 64 MB |
| Max note lifetime | 3 days | 30 days | 30 days |
| Ads | Yes | No | No |
| Branding | Always | Removable | Removable |

Usage is tracked server-side: the anonymous cap is enforced per-browser via the `cp_anon` cookie; logged-in users are capped per account by their plan.

## Ads engine

When `ENABLE_ADS=1` (default), free users see ads in three slots: **top banner**, **composer** (send page), and **receiver** (shared note page, when the sender's plan shows branding).

- `GET /api/ads?slot=top_banner|composer|receiver` — returns a random active unit and records an **impression**.
- `POST /api/ads/<id>/click` — records a **click** and 302-redirects to the advertiser URL.
- `/admin` — per-ad unit: impression/click/CTR/rev totals, edit (title/url/image), delete, add new units, plus a users table to change plans, admin flag, or disable accounts.
- Logged-in users on ad-free plans (`/api/me` → `ads: false`) never see ad slots; the page hides them.

The database is seeded with 4 demo ad units when empty (only in dev/demo). Revenue fields are illustrative — plug in a real ad network by pointing the click handler at it.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | HTTP port (`python app.py`) |
| `DB_PATH` | `./cryptopegion.db` | SQLite database file location |
| `SECRET_KEY` | random | Flask sessions (set in production!) |
| `DEMO_MODE` | `1` | `1` = upgrades happen instantly without payment (demo); `0` = production |
| `ENABLE_ADS` | `1` | `1` = serve ads to free users; `0` = disable ad engine entirely |
| `MAX_BODY_MB` | `160` | Request body size cap (protects the JSON API) |
| `ADMIN_EMAIL` | `admin@cryptopegion.local` | Auto-seeded admin account email (new DB only) |
| `ADMIN_PASSWORD` | `demo-admin-123` | Auto-seeded admin account password (new DB only) |
| `STRIPE_SECRET_KEY` | *(empty)* | Stripe API key (test: `sk_test_...`, live: `sk_live_...`). Presence enables real billing |
| `STRIPE_PRICE_ULTIMATE` | *(empty)* | Stripe monthly **Price ID** for the Ultimate plan |
| `STRIPE_PRICE_TEAMS` | *(empty)* | Stripe monthly **Price ID** per user for the Teams plan |
| `STRIPE_WEBHOOK_SECRET` | *(empty)* | Stripe webhook signing secret (`whsec_...`); enables `/api/stripe/webhook` |
| `STRIPE_ENABLED` | auto (`1` when a key is set) | `0` = force the offline DEMO_MODE fallback (instant upgrade, no charge) |

> ⚠️ **Change `ADMIN_EMAIL` / `ADMIN_PASSWORD` (and `SECRET_KEY`) before any real deployment.**

All settings above can be placed in a `.env` file next to `app.py` (copy `.env.example`). Environment variables always take precedence over `.env`.

## Real billing (Stripe)

By default the app runs in **DEMO_MODE**: clicking upgrade switches the plan instantly with no charge. To take real payments, put Stripe credentials in `.env` (or the environment):

```env
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_PRICE_ULTIMATE=price_xxx
STRIPE_PRICE_TEAMS=price_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
```

Steps:

1. **Create the products/prices** in the Stripe dashboard (or API): a recurring **monthly** price of **$23** for Ultimate and **$19** per user for Teams. Copy each `price_...` ID into the two `STRIPE_PRICE_*` values.
2. **Add a webhook endpoint** → `https://YOUR_HOST/api/stripe/webhook` subscribing to `checkout.session.completed` and `customer.subscription.deleted` (optional if you want automatic downgrades on cancel). Paste its `whsec_...` signing secret into `STRIPE_WEBHOOK_SECRET`.
3. **Restart** the app. With a key present, `STRIPE_ENABLED` becomes `1` automatically.

Behavior once enabled:

- `POST /account/upgrade` (Ultimate/Teams) creates a Stripe **Checkout Session** and redirects the buyer to the hosted checkout page. **The plan is NOT activated yet** — it stays on the current plan until payment clears.
- On a successful payment the plan activates via **either** the Checkout success page (`/account/upgrade/success`) **or** the signed webhook (`checkout.session.completed`). Both are idempotent, so a plan is never activated twice.
- Clicking “switch to Free” cancels the live Stripe subscription (if any) and downgrades immediately.
- If Stripe is reachable but misconfigured (bad key / missing price ID), upgrades return a clear 502 error instead of silently charging.

To go back to the offline demo, set `STRIPE_ENABLED=0` or remove `STRIPE_SECRET_KEY`.

## Quick start (local)

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5000
```

Admin panel: sign in with the seeded admin (default `admin@cryptopegion.local` / `demo-admin-123`, printed at first boot) → `/admin`.

## Deploy — Docker (any VPS)

```bash
docker compose up -d --build     # serves on port 8000
```

Put it behind Caddy (automatic HTTPS) with a `Caddyfile`:

```
cryptopegion.yourdomain.com {
    reverse_proxy localhost:8000
}
```

## Deploy — one-click platforms

| Platform | Steps |
|---|---|
| **Railway** | Push this folder to GitHub → New Project → Deploy from repo. `Procfile` included. Add a volume at `/app/data` for SQLite persistence. |
| **Render** | New Web Service → repo → env `Python 3` → start command `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`. |
| **Fly.io** | `fly launch` (detects Dockerfile) → `fly deploy`. |

> ⚠️ Serve over **HTTPS only** — the design depends on the `#fragment` key never reaching the server, which holds for any HTTPS deployment.

## Regenerate / extend with AI

`AI_PROMPT.md` contains a copy-paste prompt that reproduces this entire project or extends it (password-protected links, QR sharing, custom domains, etc.).

## API

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/notes` | Create: `{ct, iv, has_file, max_views, ttl_minutes}` |
| POST | `/api/notes/<id>/open` | Consume 1 view (atomic); deletes row at the limit |
| GET | `/api/notes/<id>/meta` | Availability + views left (no view consumed) |
| POST | `/api/notes/<id>/burn` | Delete immediately |
| GET | `/api/me` | Current user session: plan, limits, remaining quota, `ads` flag |
| GET | `/api/me/notes` | History of my notes (no keys — fragments are never stored) |
| GET | `/api/ads?slot=<top_banner\|composer\|receiver>` | Random active ad + records an impression |
| POST | `/api/ads/<id>/click` | Record click, redirect to advertiser |

Web pages: `/` (landing), `/pricing`, `/send`, `/note/<id>`, `/signup`, `/login`, `/account`, `/admin`. All state-changing form routes (`logout`, `/account/upgrade`, `/account/burn`, admin actions) require a CSRF token read from the page `<meta name="csrf">`.

## Tests

```bash
# Terminal 1: start the server against a throwaway database
#   (force offline: STRIPE_SECRET_KEY= STRIPE_ENABLED=0 keeps the demo-billing tests deterministic even with a .env present)
DB_PATH=/tmp/cryptopegion_e2e.db STRIPE_SECRET_KEY= STRIPE_ENABLED=0 python3 app.py

# Terminal 2: run the suite (sections: anon core, auth/plans, admin, usage caps)
DB_PATH=/tmp/cryptopegion_e2e.db python3 test_e2e.py
```

## Files

```
app.py                  Flask backend (zero-knowledge storage, atomic burns,
                        plans/limits, auth, ads engine, admin)
templates/              Jinja2 pages (base, landing, pricing, send, note,
                        signup, login, account, admin)
static/app.js           Front-end logic (composer, ads loader, session wiring)
static/crypto.js        Shared base64/WebCrypto helpers
static/site.css         Styling + ad-slot / plan-aware layout
test_e2e.py             End-to-end API + auth + caps tests
Dockerfile              Production container (gunicorn, non-root)
docker-compose.yml      One-command deploy with persistent volume
Procfile                For Railway/Render/Heroku
AI_PROMPT.md            Prompt to regenerate this project with any AI
requirements.txt        flask>=3.0, gunicorn>=21.0, python-dotenv>=1.0, stripe>=8.0
.env / .env.example     Stripe & deployment secrets (copy .env.example)
```

# Deploy link :https://cryptopegion.onrender.com/
