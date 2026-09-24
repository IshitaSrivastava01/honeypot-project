"""
Synthetic log generator modeling the actual structured JSON event log schema
from the Web Application Honeypot & Attack Detection System project
(IP, timestamp, payload, headers, endpoint, attack_type).

Data is synthetic (for demonstration) but the schema, endpoint types, and
attack categories match the real honeypot design: 5 endpoint types
(fake admin login, config exposure, API enumeration, file upload, search)
and rule-based detection for brute-force / SQLi / XSS patterns.
"""
import random
import json
import csv
from datetime import datetime, timedelta

random.seed(42)

ENDPOINTS = [
    "/admin/login",
    "/config/exposed.env",
    "/api/v1/users",
    "/upload",
    "/search",
]

ATTACK_TYPES = {
    "/admin/login": ["brute_force", "credential_stuffing", "none"],
    "/config/exposed.env": ["config_exposure_probe", "none"],
    "/api/v1/users": ["api_enumeration", "idor_probe", "none"],
    "/upload": ["malicious_file_upload", "none"],
    "/search": ["sqli", "xss", "none"],
}

SEVERITY = {
    "brute_force": "high", "credential_stuffing": "high",
    "config_exposure_probe": "medium", "api_enumeration": "medium",
    "idor_probe": "high", "malicious_file_upload": "critical",
    "sqli": "critical", "xss": "high", "none": "low",
}

PAYLOAD_SAMPLES = {
    "brute_force": "username=admin&password={guess}",
    "credential_stuffing": "username={user}&password={leaked_pw}",
    "config_exposure_probe": "GET /config/exposed.env HTTP/1.1",
    "api_enumeration": "GET /api/v1/users?id={n}",
    "idor_probe": "GET /api/v1/users?id={n}&token=none",
    "malicious_file_upload": "filename=shell.php.jpg",
    "sqli": "q=' OR '1'='1' --",
    "xss": "q=<script>alert(1)</script>",
    "none": "-",
}

def random_ip():
    # Weighted pool so some IPs repeat (simulating brute-force campaigns)
    pool = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(180)]
    return random.choice(pool)

def generate_logs(n=2500, days=45):
    start = datetime(2026, 8, 1)
    rows = []
    ip_repeat_pool = [random_ip() for _ in range(35)]  # simulate recurring attacker IPs

    for i in range(n):
        endpoint = random.choices(ENDPOINTS, weights=[30, 15, 25, 10, 20])[0]
        attack_type = random.choices(
            ATTACK_TYPES[endpoint],
            weights=[45, 55] if len(ATTACK_TYPES[endpoint]) == 2 else [35, 25, 40]
        )[0]
        ts = start + timedelta(
            days=random.uniform(0, days),
            hours=random.uniform(0, 24)
        )
        ip = random.choice(ip_repeat_pool) if random.random() < 0.55 else random_ip()
        payload = PAYLOAD_SAMPLES[attack_type]
        severity = SEVERITY[attack_type]
        detected = 1 if attack_type != "none" else 0

        rows.append({
            "event_id": f"evt_{i+1:05d}",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ip,
            "endpoint": endpoint,
            "attack_type": attack_type,
            "severity": severity,
            "payload_sample": payload,
            "detected_by_ruleset": detected,
        })

    rows.sort(key=lambda r: r["timestamp"])
    return rows

if __name__ == "__main__":
    logs = generate_logs()
    with open("honeypot_logs.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    print(f"Generated {len(logs)} log entries -> honeypot_logs.csv")