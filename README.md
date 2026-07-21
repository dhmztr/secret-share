# secret-share

Self-hosted one-time secret sharing. Paste a password, API key, or file, get back a single link. The recipient opens it, and the secret is gone — burned after the first view or after it expires, whichever comes first.

The server never sees the plaintext. Encryption happens in the browser; the key lives in the URL fragment (`#...`), which browsers never send over the wire. Postgres only ever holds ciphertext.

## How it works

Everything sensitive is done client-side before anything touches the network.

**Creating a secret**
1. The browser (Leptos/WASM) generates a random 256-bit key and encrypts the payload with ChaCha20-Poly1305.
2. If you set a password, it's hashed with Argon2 and only the hash travels to the server.
3. The ciphertext + nonce go to `POST /api/secrets`. The key does **not** — it's appended to the returned URL as `#<key>`.
4. You share `https://host/s/<uuid>#<key>`.

**Opening a secret**
1. The browser fetches metadata (`GET /api/secrets/{id}/meta`) to see if a password is needed.
2. It calls `POST /api/secrets/{id}/fetch`. The server checks the password (Argon2, constant-time), then does one atomic SQL `UPDATE` that enforces "not burned, not expired, view count under the limit" and returns the ciphertext in the same step.
3. The browser decrypts with the key from the fragment and shows the result — or offers a file download.

Because the reveal is a single atomic update, two people racing the same link can't both win the last view.

**Accounts**
Creating links requires a verified account. Registration sends a 6-digit code by email (15-minute TTL, 5 tries), and disposable/burner domains are rejected up front. Free accounts get 5 links per month; the quota refills on a rolling monthly window. Sessions are JWTs (24h).

## Architecture

Rust workspace, five crates:

| Crate | Responsibility |
|-------|----------------|
| `server` | axum HTTP + Leptos SSR host, routing, rate limits |
| `frontend` | Leptos UI, runs as WASM in the browser, does all crypto |
| `crypto` | ChaCha20-Poly1305 + Argon2, compiles to both native and WASM |
| `db` | Postgres (sqlx) and Redis access |
| `auth` | JWT issue/verify, email sending (SMTP) |

Storage: **Postgres** for users and secrets, **Redis** as a quota counter cache (synced back to Postgres every 60s, so a Redis wipe loses nothing durable).

Rate limits are per-client-IP, one bucket per endpoint:

| Endpoint | Limit |
|----------|-------|
| create / fetch / burn | 50 req/s |
| metadata | 5 req/s |
| register / login | 10 req/hour |
| verify | 20 req/hour |
| resend code | 5 req/hour |

Plus a global 30s request timeout and a 26 MB body cap.

## Running it

Requires Docker with the compose plugin. Everything runs from `docker-compose.yml` (app + Postgres + Redis, and optionally a Cloudflare tunnel).

```bash
cp .env.example .env
# fill in the values below, then:
docker compose up -d --build
```

The app listens on `8080`. Schema is applied automatically — a fresh database gets it from `migrations/init.sql`, and an existing one is patched with idempotent `ALTER`s on startup, so you never run migrations by hand.

### Configuration (`.env`)

| Variable | Notes |
|----------|-------|
| `JWT_SECRET` | Session signing key. Min 32 chars — generate with `openssl rand -base64 48`. |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | Postgres credentials. |
| `REDIS_URL` | e.g. `redis://redis:6379`. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Any STARTTLS provider (Resend, Brevo, Gmail app password…). Leave unset to run without email — accounts then need manual verification. |
| `TUNNEL_TOKEN` | Cloudflare tunnel token, if you use the bundled `cloudflared` service. |

### Putting it on the internet

The app speaks plain HTTP on 8080 — put TLS in front of it. The simplest path is a **Cloudflare tunnel**: no open inbound ports, certificates handled at the edge.

1. Create a tunnel in Cloudflare Zero Trust, drop its token into `TUNNEL_TOKEN`.
2. Point a public hostname at `http://app:8080`.
3. `docker compose up -d`.

The Postgres and Redis ports are bound to `127.0.0.1` only, so they're never exposed even though the host has a public IP.

### Deploys

Pushing to `main` triggers `.github/workflows/deploy.yml`, which SSHes into the host, pulls, and rebuilds:

```
git push  →  GitHub Actions  →  ssh host  →  git reset --hard + docker compose up -d --build
```

Set these repository secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` (a dedicated deploy key), and optionally `VPS_APP_DIR` (defaults to `~/secret-share`) and `VPS_PORT` (defaults to `22`). The build runs on the host; the container swaps once it's ready, so downtime is a few seconds.

## Security notes

- **Zero-knowledge**: the decryption key never reaches the server. Losing the link means losing the secret — by design.
- **AEAD** (ChaCha20-Poly1305) with a fresh random key per secret; passwords hashed with Argon2 on both ends.
- All SQL is parameterized (sqlx). Password checks are constant-time, and a dummy hash is verified even for non-existent secrets so response timing doesn't reveal whether a secret exists.
- The container runs as a non-root user, and standard hardening headers (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`) are set on every response.

## Development

```bash
cargo test                     # unit tests
cargo leptos watch             # local dev server with hot reload
SQLX_OFFLINE=true cargo check --workspace
```

`SQLX_OFFLINE=true` uses the committed `.sqlx/` query metadata, so you can build without a live database.
