# AI Prompt for CryptoPegion

Copy-paste the prompt below into any AI coding assistant (ChatGPT, Claude, Cursor, etc.) to regenerate or extend this project.

---

**PROMPT:**

Build a complete, production-ready web app called **CryptoPegion** using Python Flask (backend) and vanilla HTML/CSS/JS (frontend, no build step). It is a zero-knowledge platform for sharing fully encrypted, self-destructing notes and files with one click.

## Core security model (mandatory)
- Browser-side encryption only: generate a random AES-256-GCM key with the WebCrypto API, encrypt the note (and optional file) BEFORE upload. Use a fresh random 12-byte IV per note.
- Put the key ONLY in the URL fragment (`/note/<id>#<base64url-key>`). The fragment is never sent to the server, so the server can never decrypt anything. The server stores only ciphertext (BLOB), IV, and metadata.
- Use HTTPS-only cookies/no logging of content in production; serve behind a reverse proxy.

## Sender page (/)
- Centered card layout, dark theme, with a **big note box in the middle** of the page.
- Exactly two toggle switches under the note box:
  1. **File** — ON/OFF switch. When ON, show a file picker (click or drag-and-drop) that encrypts and attaches one file (~10 MB max) together with the note.
  2. **Advanced** — ON/OFF switch that reveals:
     - **Views limit**: number input (1–100, default 1). After the link has been opened that many times, the note is deleted from everywhere permanently (database row removed in the same atomic request).
     - **Minutes timer**: another ON/OFF sub-toggle ("Auto-expire after") with a dropdown (5 min / 1 hour / 1 day / 7 days). When ON, the note is deleted automatically when the time runs out, even if never opened.
- On submit: encrypt in the browser, POST the ciphertext to `POST /api/notes` (`{ct, iv, has_file, max_views, ttl_minutes}`), then show the shareable link with a big warning to copy it now (the #key is unrecoverable).

## Receiver page (/note/<id>)
- Pre-check `GET /api/notes/<id>/meta` WITHOUT consuming a view; show how many views remain and whether a file is attached.
- Require an explicit "Open & decrypt" button, then `POST /api/notes/<id>/open`, which atomically increments `views_used` and **DELETEs the row when views_used >= max_views** (return `burned: true`).
- Show the decrypted note; if a file is attached show a file card with a **Download** button (Blob object URL) — the file also exists only until the view limit burns it.
- Include a "Burn now" button to delete the note immediately.
- If the note is gone/expired, show a friendly "This note is gone" screen (deleted after its view limit was reached, expired, or never existed).

## Backend requirements
- SQLite table: `notes(id TEXT PK, ct BLOB, iv BLOB, has_file INT, max_views INT, views_used INT, expires_at REAL)`.
- All view consumption must be atomic (single UPDATE ... WHERE views_used < max_views AND not expired), safe against race conditions and concurrent opens.
- Endpoints: `POST /api/notes`, `POST /api/notes/<id>/open`, `GET /api/notes/<id>/meta`, `POST /api/notes/<id>/burn`. Validate max_views (1..100), ttl (1..10080 min), payload size (10 MB), base64 integrity; return JSON errors.
- Include a production `Dockerfile` + `docker-compose.yml` (gunicorn), a README with deployment steps (VPS with Caddy/Nginx, Railway/Render/Fly.io), and an automated end-to-end API test script (create → meta → open × N → burn → expiry → validation errors).

## Frontend polish
- Dark gradient background, glassmorphism cards, custom CSS toggle switches, drag-and-drop file zone, copy-to-clipboard button, mobile responsive, no external CDNs (works offline).

Deliver every file in full: `app.py`, `templates/index.html`, `templates/note.html`, `static/crypto.js`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `README.md`, `test_e2e.py`.
