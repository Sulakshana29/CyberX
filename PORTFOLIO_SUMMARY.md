# CyberX v2 — Portfolio Project Summary

## What It Is

CyberX is a full-stack web vulnerability scanner built with Python + Flask.
It covers all 10 OWASP Top 10 (2021) categories and is deployed as a REST API
with a real-time web dashboard.

---

## Technical Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Flask 2.3 |
| Scanner Engine | Custom-built (no Nikto/ZAP wrappers) |
| Database | SQLite with WAL mode (thread-safe concurrent access) |
| Production server | Gunicorn (multi-worker) |
| Containerisation | Docker multi-stage build, non-root user, HEALTHCHECK |
| Deploy config | render.yaml (one-click Render.com deploy) |
| CI | GitHub Actions — runs on every push |

---

## OWASP Coverage (A01–A10)

| Category | What's Tested |
|---|---|
| **A01** Broken Access Control | IDOR detection (21 param patterns), forced-browsing admin paths, robots.txt-augmented path probing |
| **A02** Cryptographic Failures | HTTP plaintext, invalid TLS cert, missing HSTS |
| **A03** Injection | Error-based SQLi (GET/POST/headers), time-based blind SQLi (aggressive mode), reflected XSS with HTML-decode bypass, command injection, LDAP injection, NoSQL injection |
| **A04** Insecure Design | Path traversal (5 encodings), open redirect |
| **A05** Security Misconfiguration | 6 missing security headers, server version disclosure, dangerous HTTP methods (TRACE/CONNECT/PUT/DELETE with severity tuning), debug endpoints, directory listing |
| **A06** Vulnerable Components | Version extraction from headers, known-CVE version flagging (Apache/nginx/PHP/ASP.NET) |
| **A07** Auth Failures | Insecure cookie flags, HTTP Basic over HTTP, default credential probing |
| **A08** Integrity Failures | Missing Subresource Integrity on CDN scripts/stylesheets |
| **A09** Logging Failures | Framework debug pages, verbose stack-trace error responses |
| **A10** SSRF | URL-param injection → localhost + AWS metadata, blind SSRF via timing |

---

## Key Engineering Decisions

### 1. Canary-token XSS detection
Instead of checking if a payload appears in the response, the scanner injects a
cryptographically unique token inside each XSS vector and checks that both the
token AND the raw payload are reflected (handling HTML-entity encoding too).
This eliminates false positives from coincidental string matches.

### 2. CVSS v3.1 scoring from scratch
Implements the full CVSS 3.1 base score formula including Scope-Changed impact
calculation. Not hardcoded numbers — actual metric inputs produce correct scores:
- Unauthenticated error-based SQLi → **9.8 CRITICAL**
- Reflected XSS (UI=Required, Scope=Changed) → **6.1 MEDIUM**

### 3. Thread-safe in-memory scan store
`active_scans` is guarded by `threading.Lock()` with a copy-on-read pattern.
A background daemon evicts entries older than 1 hour to prevent memory leaks.

### 4. robots.txt-augmented path probing
Before probing admin and debug paths, the scanner fetches `/robots.txt` and
adds Disallowed paths to its probe list. These are often hidden for a reason.

### 5. Retry with exponential back-off
`_get()` and `_post()` retry on `Timeout` exceptions with 0.5s × attempt
back-off. Configurable via `max_retries` (default 1).

### 6. Aggressive mode adds blind SQLi + link crawling
- Time-based blind SQLi payloads (MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR DELAY`)
- Single-level same-domain link crawler to auto-discover parameterised endpoints

### 7. Rate limiting
`flask-limiter` limits scan submissions to 10 per minute per IP, with a global
200/day and 50/hour default. Prevents API abuse in shared deployments.

---

## Production Infrastructure

```
app.py
├── Rate limiting      (flask-limiter, 10 scans/min per IP)
├── URL validation     (scheme + host check before scanning starts)
├── Thread-safe store  (threading.Lock on all active_scans mutations)
├── Memory eviction    (background thread, 1-hour TTL)
├── Error sanitisation (raw tracebacks hidden in production mode)
└── Scan duration      (accurately measured per-URL, shown in reports)

scanner/owasp_scanner.py
├── 17 scan checks     (16 default + blind SQLi in aggressive mode)
├── robots.txt cache   (fetched once per origin, shared across A01+A05)
├── crawl_links()      (same-domain href extraction, capped at 20 URLs)
└── Retry logic        (Timeout-specific retry with back-off)

scanner/database.py
├── WAL mode SQLite    (concurrent readers + background writer)
├── Bulk INSERT        (executemany for findings)
└── Indexed queries    (scan_id index on findings, started_at on scans)
```

---

## Test Suite

18 unit tests — all passing:

| Class | Tests |
|---|---|
| `TestSQLInjectionScanner` | URL param extraction, DB fingerprinting (MySQL/PostgreSQL/SQLite), network error handling, CVSS score validation |
| `TestXSSScanner` | Canary generation, verbatim + escaped reflection detection, CVSS score validation |
| `TestConfiguration` | All 3 profile modes (default/aggressive/stealth) |
| `TestReporting` | ScanResult creation, dict serialisation, JSON report generation |

Run with: `pytest test_cyberscan.py -v`

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/scan` | POST | Start a scan. Body: `{urls, timeout, mode, bearer_token, session_cookie}` |
| `GET /api/scan/<id>/status` | GET | Live progress polling (progress %, current test, vulns found) |
| `GET /api/scan/<id>/results` | GET | Full findings list with severity summary |
| `GET /api/report/<id>/<fmt>` | GET | Download report (`html`, `json`, `csv`) |
| `GET /api/history` | GET | All past scans (last 50) |
| `GET /health` | GET | Health check for load balancers / Docker HEALTHCHECK |

---

## Deployment

### Docker
```bash
docker build -t cyberx .
docker run -p 5000:5000 -e CYBERX_API_KEY=your-key cyberx
```

### Render.com (one-click)
1. Fork the repo on GitHub
2. Connect to [render.com](https://render.com)
3. New → Blueprint → point at your fork (uses `render.yaml`)
4. Done — Render auto-generates an API key and mounts a persistent disk

---

## What This Demonstrates for Employers

| Skill | Evidence |
|---|---|
| Security engineering | Custom OWASP scanner, CVSS 3.1 implementation, canary-token XSS, blind SQLi |
| Systems programming | Thread safety, retry logic, WAL-mode SQLite, memory management |
| API design | RESTful routes, auth headers, rate limiting, structured error responses |
| DevOps awareness | Dockerfile multi-stage build, GitHub Actions CI, Render deploy config |
| Code quality | Type hints, docstrings, 18 unit tests, no external scanner dependencies |
| Accuracy engineering | False positive tuning (PUT/DELETE, SSRF timing, XSS encoding) |

---

**CyberX v2.0** — Built by Sulakshana
