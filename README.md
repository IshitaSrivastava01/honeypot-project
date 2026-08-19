# Web Application Honeypot & Attack Detection System

A multi-endpoint honeypot built to simulate common vulnerable web application surfaces, capture real attacker/scanner behavior, and detect basic attack patterns (brute-force, SQL injection, XSS) in real time.

**Live demo:** https://honeypot-project-0gt6.onrender.com

> Note: as a honeypot, this application intentionally *looks* vulnerable to attract probing traffic. No real user data, credentials, or exploitable vulnerabilities are present — see [Security & Isolation](#security--isolation) below.

---

## Why I built this

As a Cyber Security undergraduate with hands-on experience assessing web application vulnerabilities (SQLi, XSS, CSRF) during a security internship, I wanted to go a step further than *finding* vulnerabilities — I wanted to understand attacker behavior directly, by building a system designed to attract and observe it. This project let me apply real security engineering (secure logging, input handling, deception design) rather than just studying it.

---

## Architecture

```
                        ┌─────────────────────┐
   Internet traffic --> │   Express Server     │
   (bots, scanners,     │   (Render, public)   │
    manual testing)     └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
             Fake Endpoints   Detection Logic   Structured Logging
             (5 traps)        (brute-force,     (JSON events)
                               SQLi/XSS regex)         │
                                                        ▼
                                              ┌──────────────────┐
                                              │  MongoDB Atlas    │
                                              │  (persistent log  │
                                              │   storage)         │
                                              └──────────────────┘
```

## Fake Endpoints (Traps)

| Endpoint | Method | Simulates | Response |
|---|---|---|---|
| `/admin/login` | POST | Admin panel brute-force target | 401 Unauthorized |
| `/.env` | GET | Exposed environment/config file | 404 Not Found |
| `/api/users` | GET | Insecure API leaking user data | 403 Forbidden |
| `/search` | GET | Search feature vulnerable to SQLi/XSS | 200, generic "no results" |
| `/upload` | POST | Insecure file upload endpoint | 500 Internal Server Error |

Each endpoint returns a realistic, generic response (not an obvious error), so it doesn't reveal itself as a honeypot to a scanning tool or attacker.

## Structured Logging

Every request to a trap endpoint is captured as a structured event and stored in MongoDB Atlas (chosen over SQL for flexible, JSON-shaped event data and to survive server restarts on free hosting). Each event includes:

- Timestamp
- Source IP
- Endpoint & HTTP method
- User-Agent
- Payload/query (where applicable)
- Event type
- Detection flags (see below)

## Attack Detection

Two rule-based detectors are implemented:

**Brute-force detection** — tracks login attempts per IP in a rolling 30-second window. More than 3 attempts in that window flags the event as `flagged_brute_force: true`.

**SQL Injection / XSS detection** — the `/search` endpoint's query parameter is checked against regex patterns for common SQLi indicators (`OR`, `UNION`, `SELECT`, quote characters, comment sequences) and XSS indicators (`<script>`, `javascript:`, inline event handlers). Matches are tagged with `detected_attack_type`.

## A real vulnerability I found (and fixed)

While building the `/search` endpoint, I initially reflected the user's raw query directly back in the HTTP response. Testing it with `<script>alert(1)</script>` caused the script to actually execute in my browser — I had unintentionally built a real, exploitable reflected XSS vulnerability rather than a simulated one.

I fixed this by logging the attempted payload (for detection purposes) without ever reflecting raw input back in the response — the honeypot needs to *look* vulnerable, not *be* vulnerable, especially once deployed publicly.

## Security & Isolation

- No real user data, credentials, or secrets exist anywhere in the system
- Fake endpoints never process or store real files/data — uploads are logged (filename, type, size) but not served back or executed
- MongoDB access is credential-protected; database user has minimal required permissions
- Hosted on Render's free tier, isolated from any personal infrastructure

**Known limitations (honestly noted):**
- Network access for the database is currently open (`0.0.0.0/0`) for simplicity during development — a production system would restrict this to specific IPs
- No rate limiting beyond brute-force detection/logging (requests aren't blocked, only flagged)
- Single-server deployment; no correlation of requests into attack "sessions" yet (see Future Improvements)

## Tech Stack

Node.js, Express, MongoDB Atlas, deployed on Render.

## Findings

*(Live and updating — last checked Aug 19, 2026, ~1 day after deployment.)*

- Total requests captured so far: small initial sample (single-digit to low double-digit range), collection ongoing through the deployment window
- Traffic sources so far: manual testing from multiple networks/locations (Chennai, Haridwar) to validate real-world IP capture; organic/automated traffic expected to accumulate over the following days
- Most-targeted endpoint so far: `/.env` and `/search`
- Most common detected attack type so far: none yet flagged from external traffic (test queries used benign strings); detection logic has been separately verified with deliberate SQLi/XSS/brute-force test payloads (see Attack Detection section)
- Notable observation / real bug found during deployment: the app initially logged all visitor IPs as `::1` (localhost) due to Render's reverse proxy masking the real client IP. Fixed by enabling `app.set('trust proxy', true)` in Express, after which real public IPs (e.g., `152.57.94.221`) were correctly captured. This was an important catch, since accurate IP data is foundational to the brute-force detection logic.
- Final numbers and any organic attacker patterns will be added closer to the end of the observation window.

## Future Improvements

Given more time, the next additions would be:
- **Session correlation** — grouping multiple requests from the same IP into a coherent attack timeline (recon → brute-force → injection attempt)
- **A monitoring dashboard** — real-time view of recent attacks, categories, and charts
- **IP geolocation** — visualizing where traffic originates
- **Additional detection types** — path traversal, command injection
- **Rate limiting / active blocking**, not just passive flagging

## What I learned

Building this project reinforced how much of security engineering is about designing realistic deception, not just detecting known attack signatures. Debugging a real XSS vulnerability I introduced myself gave me a much more concrete understanding of *why* input sanitization matters than reading about it during my internship ever did.