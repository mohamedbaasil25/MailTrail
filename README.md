# MailTrail — Email Threat Detection & Forensic Analysis Platform

MailTrail analyzes inbound emails for phishing, business-email-compromise, and
infrastructure-level threat indicators, then produces a tamper-evident
forensic record for each one — an ensemble risk score, a hash-chained
evidence vault, a searchable investigation UI, and submission-ready PDF
reports. It was built for the Smart India Hackathon problem statement
SIH26106 and has since gone through several rounds of security/production
hardening (see [Security](#security) below).

> **Status**: this is a working, tested MVP with a real ensemble detection
> pipeline and a genuinely hardened backend — but it is not a certified,
> commercially-supported forensic tool. Read the [Known limitations](#known-limitations)
> section before relying on it for anything higher-stakes than a demo or an
> internal proof of concept.

---

## Contents

- [How detection works](#how-detection-works)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Running the test suite](#running-the-test-suite)
- [Maintenance scripts](#maintenance-scripts)
- [Deployment](#deployment)
- [Security](#security)
- [API overview](#api-overview)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)

---

## How detection works

Every analyzed email is scored by five independent signal sources, combined
into a single 0–100 risk score:

| Signal source | What it checks |
|---|---|
| **Heuristics** | Urgency/pressure language, credential & payment lures, insecure/shortened/lookalike links, brand-impersonation domains (including the *sender's own* domain, not just links in the body) |
| **NLP classifier** | A transformer-based phishing classifier (optional — see [Configuration](#configuration); degrades gracefully to heuristics-only when disabled or unavailable) |
| **DNS authentication** | SPF and DMARC record validation against the sender's actual domain |
| **Geo Intelligence** | Extracts the sender IP from `Received:` headers, resolves it to a location, and flags **impossible travel** — a physically-implausible jump between this sender's current and previous known location (the same underlying idea as account-takeover detection, applied to sender infrastructure) |
| **Threat intelligence** | Looks up extracted domains/IPs against a VirusTotal-v3-compatible API, with retry/backoff and graceful degradation if the provider is unreachable |

Every analysis is written to a hash-chained evidence vault (each record's
hash incorporates the previous record's hash — a lightweight tamper-evidence
ledger you can verify via `GET /api/v1/verify-chain`), fully searchable by
sender, recipient, subject, or sender IP, and exportable as a formatted PDF.

## Architecture

```
┌─────────────┐      ┌──────────────────────────────┐      ┌─────────────┐
│  Frontend   │─────▶│         FastAPI backend        │─────▶│  MongoDB    │
│ (vanilla JS │ REST │  api/routes.py, api/auth.py    │      │ evidence    │
│  ES modules,│  +   │  ┌────────────────────────┐   │      │ vault +     │
│  no build   │  WS  │  │ services/               │   │      │ audit log   │
│  step)      │      │  │  heuristic_engine       │   │      └─────────────┘
└─────────────┘      │  │  nlp_analyzer           │   │
                      │  │  dns_validator          │   │      ┌─────────────┐
                      │  │  geoip_service ─────────┼───┼─────▶│  MaxMind    │
                      │  │  threat_intel_service ──┼───┼─────▶│  GeoLite2 / │
                      │  │  forensic_service       │   │      │  VirusTotal │
                      │  │  http_client (retry)    │   │      └─────────────┘
                      │  └────────────────────────┘   │
                      └──────────────────────────────┘
```

The frontend is deliberately dependency-free — plain HTML/CSS and native
ES modules served as static files, no build step, no bundler. `services/`
holds one focused module per concern; `services/http_client.py` implements
shared retry-with-exponential-backoff-and-jitter logic used by both the
threat-intel integration and the GeoIP database updater script.

## Tech stack

- **Backend**: FastAPI (async), Uvicorn/Gunicorn, MongoDB via Motor
- **Auth**: PyJWT (HS256), bcrypt password hashing, httponly cookie sessions, RBAC (admin/analyst)
- **Frontend**: Vanilla JavaScript (ES modules), HTML5, CSS3 — no framework, no build step
- **Detection**: `dnspython` (SPF/DMARC), `geoip2` (MaxMind GeoLite2), optional `transformers` phishing classifier, `requests` for outbound threat-intel calls
- **Reporting**: `fpdf2` for PDF generation
- **Testing**: `pytest` + `pytest-asyncio`, `mongomock-motor` for DB-free unit tests
- **Deployment**: Docker (Gunicorn + Uvicorn workers), Docker Compose, Caddy (TLS termination), Render-ready

## Getting started

### Option A — Docker Compose (recommended)

```bash
git clone <this-repo>
cd mailtrail
cp .env.example .env          # then edit .env - see Configuration below
docker compose up -d --build
```

- Web app: `http://localhost:8000`
- API docs (Swagger UI): `http://localhost:8000/docs`

This starts both MongoDB and the backend. The dev compose file mounts your
source tree into the container and runs Uvicorn with `--reload`, so code
changes apply without a rebuild.

### Option B — Local Python environment

Requires Python 3.10+ and a running MongoDB instance.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env              # edit MONGO_URI etc.
uvicorn main:app --reload
```

### First login

Local/dev defaults (bcrypt hashes already in `config.py`, **not** valid in
production — see [Security](#security)):

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Analyst | `analyst` | `analyst123` |

Generate a real bcrypt hash for production credentials:

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'your-real-password', bcrypt.gensalt()).decode())"
```

## Configuration

All configuration is environment-variable driven — see `.env.example` for
the full, commented list. The essentials:

| Variable | Required | Purpose |
|---|---|---|
| `MONGO_URI`, `MONGO_DB_NAME` | Yes | Database connection |
| `JWT_SECRET_KEY` | Yes (prod) | Signs session tokens. **The app refuses to start in production (`ENV=production`) if this is still the shipped default.** |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | Yes (prod) | Same fail-fast protection applies to the default admin/analyst credential hashes |
| `ALLOWED_ORIGIN` | Yes (prod) | Comma-separated frontend origin(s). A wildcard `*` is rejected at startup in production — it's silently non-functional with cookie-based auth anyway |
| `ENV` | Recommended | Set to `production` to activate the startup guards above plus HSTS headers |
| `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` | Optional | Enables real GeoIP lookups via `scripts/update_geoip_db.py` (see below). Without it, Geo Intelligence uses a clearly-labeled simulated fallback |
| `THREAT_INTEL_API_KEY` | Optional | VirusTotal-v3-compatible API key for domain/IP reputation checks |
| `RATE_LIMIT_STORAGE_URI` | Recommended (multi-instance) | Point at Redis (`redis://...`) so rate limits are enforced consistently across multiple workers/replicas, not per-process |
| `ENABLE_HEAVY_NLP` | Optional | Toggles the transformer-based phishing classifier (CPU/memory heavy; the app runs fine on heuristics alone with this off) |
| `WEB_CONCURRENCY` | Optional | Gunicorn worker count in the Docker image (default 2) |

## Running the test suite

```bash
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
pytest tests/ -v
```

The suite runs against `mongomock-motor` in CI (no live MongoDB required for
unit tests) and against a real MongoDB service container in the GitHub
Actions workflow (`.github/workflows/ci.yml`) for closer-to-production
coverage.

## Maintenance scripts

Two Python automation scripts, both in `scripts/`, both built on the same
retry-with-backoff HTTP client used for the threat-intel integration:

- **`scripts/update_geoip_db.py`** — downloads/refreshes the MaxMind
  GeoLite2-City database. Run it periodically (MaxMind publishes updates
  roughly weekly) via cron or a scheduled CI job:
  ```bash
  python scripts/update_geoip_db.py
  python scripts/update_geoip_db.py --check   # exit 0 if a DB is already present
  ```
- **`scripts/security_scan.py`** — runs `pip-audit` (dependency CVE
  scanning) and `bandit` (static analysis) and returns a non-zero exit code
  on any finding, so it's wired into CI as an advisory (non-blocking)
  `security-scan` job:
  ```bash
  python scripts/security_scan.py            # both tools
  python scripts/security_scan.py --bandit-only
  ```

## Deployment

### Docker (production)

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

This runs the backend behind Caddy (automatic TLS via Let's Encrypt for a
real domain, or plain HTTP for an IP address) and serves it with Gunicorn +
Uvicorn workers rather than a single Uvicorn process. The image runs as a
non-root user and exposes a `HEALTHCHECK` that hits the DB-aware readiness
endpoint (`/api/v1/health`), not just "is the process alive."

Set `DOMAIN=your.domain.com` in the environment for Caddy to provision a
real certificate; omit it to fall back to plain HTTP on `localhost`.

### Render

`render.yaml` is included and ready to use — connect the repo in the Render
dashboard and it will pick up the config automatically. You still need to
set, in the dashboard (deliberately not committed to the repo):
`MONGO_URI` (e.g. a MongoDB Atlas connection string), `ADMIN_USERNAME`/
`ADMIN_PASSWORD_HASH`, and `ALLOWED_ORIGIN` (your real frontend origin —
the deploy will fail fast with a clear error if this is left as a wildcard).

### Any other container host

The image is a standard Docker image exposing `$PORT` (defaults to 8000)
with a working `HEALTHCHECK` — it should run as-is on Railway, Fly.io, ECS,
Cloud Run, or similar. Point the platform's health check at
`/api/v1/health`.

## Security

This project has been through several audit passes. Current state:

- **Auth**: bcrypt password hashing, JWT sessions via PyJWT (migrated off
  `python-jose` after `pip-audit` flagged a transitive `ecdsa` CVE with no
  upstream fix), httponly cookies, role-based access control
- **Startup guards**: refuses to boot in production with default admin/
  analyst credentials, a default `JWT_SECRET_KEY`, or a wildcard CORS origin
- **Rate limiting**: per-IP limits on auth and analysis endpoints, with
  optional Redis-backed storage for correct behavior across multiple
  workers/instances (see `RATE_LIMIT_STORAGE_URI` above)
- **Response headers**: `X-Content-Type-Options`, `X-Frame-Options`,
  `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, and
  `Strict-Transport-Security` (production only) on every response —
  see `security_headers.py` for the exact policy and its one known,
  documented limitation (inline `onclick=`/`style=` usage in the frontend
  means the CSP currently allows `'unsafe-inline'` for script/style; see the
  comment in that file for the concrete follow-up)
- **Input handling**: sender/recipient are normalized (display-name headers
  stripped to the bare address) and validated before anything derives an
  SPF/DMARC/geo lookup from them; PII redaction is applied only to true
  free-text fields, not to structured identity fields
- **Dependency & static analysis**: `pip-audit` and `bandit` both run clean
  as of this writing — see `scripts/security_scan.py`, wired into CI
- **Secrets hygiene**: `.env` is excluded from the Docker build context via
  `.dockerignore` (never baked into an image layer); Mongo connection
  strings are redacted before being logged

Run `python scripts/security_scan.py` yourself before deploying to confirm
nothing has regressed since this was written.

## API overview

Full interactive documentation is available at `/docs` (Swagger UI) once
the app is running. Highlights:

| Endpoint | Method | Notes |
|---|---|---|
| `/api/v1/auth/token` | POST | Login, sets an httponly session cookie |
| `/api/v1/analyze` | POST | Runs the full detection pipeline on a submitted email |
| `/api/v1/emails` | GET | Lists all analyzed records (evidence vault) |
| `/api/v1/vault/search` | GET | Full-text search across sender/recipient/subject/IP |
| `/api/v1/report/{message_id}` | GET | Downloads the generated forensic PDF |
| `/api/v1/verify-chain` | GET | Verifies the evidence hash chain's integrity |
| `/api/v1/investigations` | DELETE | Admin-only, requires a `reason` (≥10 chars), audit-logged |
| `/api/v1/health` | GET | Readiness probe (pings MongoDB) |
| `/api/health` | GET | Liveness probe (process-only, no DB dependency) |

## Printing reports

Open **Forensic reports**, choose a record, click **Generate report**, then
print (Ctrl/Cmd+P) or use the **Print / save as PDF** button. All print
styling lives in `frontend/print.css`, linked with `media="print"` so it can
never affect the on-screen dark UI.

- Clean light page, dark ink, A4 with a running footer and page numbers
- The "Choose a record" panel prints the selected record plus a compact list
  of the available records (a native dropdown only ever prints its selected
  option). The list shows the 12 most recent, always includes the chosen
  record, and notes how many more exist
- Signal-table headers repeat across pages; sections and hash blocks are not
  split mid-block; typed investigator notes print in full (a raw `<textarea>`
  would clip them)
- Risk pills use `print-color-adjust: exact`. A web page cannot tick the
  browser's own **Background graphics** checkbox; if a pill prints without
  its fill, enable that option - pills keep a border and dark text either
  way, so nothing depends on the fill to be legible
- The running page-number footer uses `@page` margin boxes, which older
  browser engines ignore (the content still prints fine; the server-generated
  PDF from `/api/v1/report/{id}` is unaffected)

## Project structure

```
api/            FastAPI routers - routes.py (analysis/vault/reports), auth.py
services/       One module per concern - heuristics, NLP, DNS, GeoIP,
                threat intel, forensic PDF generation, retry-capable HTTP client
models/         Pydantic request/response schemas
frontend/       Static SPA - index.html + js/ (ES modules) + styles.css + print.css
scripts/        Maintenance automation - GeoIP updater, security scanner,
                Docker healthcheck
tests/          Pytest suite (API integration + isolated service unit tests)
security_headers.py   Response-header middleware
rate_limiter.py        Shared slowapi Limiter instance
```

## Known limitations

Documented deliberately, not hidden:

- **CSP allows inline scripts/styles** because the frontend uses inline
  `onclick=`/`style=` attributes extensively. Real value (blocks third-party
  script/style injection and framing) without pretending to be a strict
  nonce-based policy it doesn't enforce.
- **Vault free-text search (`$text`) is untested against a live MongoDB in
  this repo's own test suite** — the mocking library used for fast unit
  tests doesn't implement MongoDB's `$text` operator. The empty-query path
  (list all records) is tested directly; the keyword-search path follows the
  same established pattern as the already-working sender/subject index, just
  extended to more fields — worth a manual smoke test after deploying
  against real MongoDB.
- **In-memory WebSocket broadcast** (`ConnectionManager` in `api/routes.py`)
  does not fan out across multiple instances — a live-update pushed on one
  instance won't reach a client connected to another. Fine for a single
  instance; would need a pub/sub backend (e.g. Redis) to scale horizontally.
- **This is an MVP heuristic/ensemble scorer**, not a trained, validated
  detection model, and has not been through a third-party security audit.
  Treat its verdicts as investigative signal, not ground truth.
