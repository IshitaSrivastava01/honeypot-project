# Web Application Honeypot & Attack Detection System

A web application honeypot built to simulate common vulnerable endpoints, capture real and test attack traffic, detect basic attack patterns (brute-force, SQL injection, XSS), and analyze captured events through a Python-based security analytics dashboard.

**Live Demo:** https://honeypot-project-0gt6.onrender.com

> This is an educational security project. The fake endpoints do not contain real user data, credentials, or exploitable production functionality.

---

## Why I Built This

As a Cyber Security undergraduate, I wanted hands-on experience with the full lifecycle of a security monitoring system — not just detecting attacks, but capturing, logging, and analyzing them the way a real security tool would. This project let me combine web application security, honeypot/deception design, and data analysis in one system.

This project involved practicing:
- Web application security
- Honeypot and deception design
- Rule-based attack detection
- Structured security logging
- Security data analysis (Python/Pandas)

---

## Architecture

```text
Incoming Request
       |
       v
Express Honeypot Server
       |
       +---- Fake Endpoints
       |
       +---- Detection Rules
       |
       v
Structured Logs (attacks.log / MongoDB)
       |
       v
Python + Pandas Analytics (analyze.py)
       |
       v
Security Dashboard (dashboard.html)
```

## Fake Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/admin/login` | POST | Brute-force detection |
| `/.env` | GET | Configuration/secret exposure probe |
| `/api/users` | GET | API enumeration |
| `/search` | GET | SQL injection and XSS detection |
| `/upload` | POST | File upload monitoring |

Each endpoint is designed to look realistic to scanners and attackers while remaining fully isolated from any real application data.

## Attack Detection

Detection is currently rule-based:

**Brute-force detection** — repeated login attempts from the same IP within a short rolling time window are tracked and flagged as suspicious.

**SQL injection detection** — the `/search` endpoint checks input for common SQLi indicators (`OR`, `UNION`, `SELECT`, quote characters, comment sequences).

**XSS detection** — the same endpoint checks for common XSS indicators (`<script>`, `javascript:`, inline event handlers). Input is normalized (URL-decoded and lowercased) before matching to catch basic encoding/case-based evasion.

## Security Logging

Each captured event includes:
- Timestamp
- Source IP
- Endpoint
- HTTP method
- User-Agent
- Request/query data
- Event type
- Detection result

Events are stored as structured JSON, enabling later analysis rather than relying on unstructured console output.

## Security Analytics Dashboard

A Python + Pandas analytics layer (`analytics/analyze.py`) processes captured log data and generates `dashboard_data.json`, which powers a dashboard (`dashboard.html`) displaying:
- Total events
- Detected attacks
- Unique attacker IPs
- Detection rate
- Attack types
- Peak attack hour
- Most-targeted endpoints
- Attack activity over time

### Data Note — Real vs. Synthetic

The repository includes a synthetic data generator (`analytics/generate_data.py`) used **only** to test and validate the analytics pipeline before connecting it to real data — this produced a 2,500-event test dataset used purely for development.

**The dashboard's actual analysis is based on real captured events in `attacks.log`**, not the synthetic dataset. As of the latest run, the real log contains:

- **29** total events
- **23** detected attacks
- **2** unique source IPs
- **79.3%** detection rate
- Peak activity around **15:00**
- **`/.env`** as the most-targeted endpoint
- **Brute-force** as the most common detected attack type

This distinction is intentional and disclosed here to avoid presenting synthetic test data as real attacker traffic. Given Render's free-tier hosting and the deployment's limited public lifetime so far, real traffic volume is modest — organic scanner/bot traffic depends on the URL being discovered, which takes time.

## A Real XSS Issue I Found and Fixed

While building the `/search` endpoint, I initially reflected the user's raw query directly into the HTTP response. Testing with:

```
<script>alert(1)</script>
```

caused the script to actually execute in my browser — I had unintentionally created a real, exploitable reflected XSS vulnerability rather than a simulated one.

I fixed this by removing raw user input from the response entirely, while still logging the attempted payload for detection purposes. The honeypot needs to *look* vulnerable to attract traffic, not *be* vulnerable once deployed publicly.

## Deployment

The application is deployed on Render.

During deployment, all requests initially appeared to originate from `localhost` (`::1`) because Render's reverse proxy was masking the real client IP. I fixed this by configuring Express to trust the deployment proxy:

```javascript
app.set('trust proxy', true);
```

After this fix, real public client IPs were correctly captured — this was an important catch, since accurate IP data is foundational to the brute-force detection logic.

## Tech Stack

- **Backend:** Node.js, Express.js
- **Database:** MongoDB Atlas
- **Analytics:** Python, Pandas
- **Frontend (dashboard):** HTML, CSS, JavaScript
- **Deployment:** Render

## Project Structure

```
honeypot-project/
├── index.js
├── attacks.log
├── README.md
├── package.json
│
├── analytics/
│   ├── analyze.py
│   ├── dashboard.html
│   ├── dashboard_data.json
│   ├── generate_data.py
│   └── honeypot_logs.csv
│
└── uploads/
```

## Known Limitations

- Detection is currently rule-based (regex/threshold-based), not behavioral or ML-based
- Public traffic volume is limited, given the deployment's short lifetime and free-tier hosting
- Suspicious requests are logged and flagged, but not automatically blocked
- Attack sessions from the same source are not yet correlated into a timeline
- MongoDB network access is currently open (`0.0.0.0/0`) for development simplicity
- Intended for educational/portfolio use rather than production security monitoring

## Future Improvements

- Session-based attack correlation (grouping related requests into an attack timeline)
- Path traversal and command injection detection
- Rate limiting and active blocking, not just passive flagging
- IP geolocation
- Dashboard filtering and alerting

## What I Learned

This project gave me practical, end-to-end experience across web security, honeypot design, structured logging, rule-based attack detection, deployment, and security data analysis with Python/Pandas.

It also taught me how infrastructure details — like reverse proxies masking client IPs — can silently affect security monitoring accuracy, and reinforced why safe input handling matters even in a system explicitly designed to look vulnerable.