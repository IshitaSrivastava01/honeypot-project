"""
Simple analytics for the honeypot's real attack log.
Reads attacks.log and creates dashboard_data.json.
"""

import json
import pandas as pd

# Real honeypot log is one folder above analytics/
LOG_FILE = "attacks.log"
OUTPUT_FILE = "dashboard_data.json"


# -----------------------------
# 1. Read real honeypot logs
# -----------------------------

events = []

with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

df = pd.DataFrame(events)

if df.empty:
    print("No log data found.")
    exit()


# -----------------------------
# 2. Clean basic fields
# -----------------------------

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["ip"] = df["ip"].astype(str)
df["endpoint"] = df["endpoint"].astype(str)


# -----------------------------
# 3. Identify attack type
# -----------------------------

def get_attack_type(row):

    # Brute force
    if row.get("flagged_brute_force") is True:
        return "brute_force"

    # XSS / SQL injection
    detected = row.get("detected_attack_type")

    if detected == "xss_attempt":
        return "xss"

    if detected == "sqli_attempt":
        return "sqli"

    # Other honeypot events
    event_type = row.get("eventType")

    if event_type == "env_scan":
        return "config_exposure"

    if event_type == "user_enumeration":
        return "api_enumeration"

    if event_type == "file_upload_attempt":
        return "file_upload"

    # Login attempts which were not flagged
    if event_type == "login_attempt":
        return "none"

    # Search requests without a detected attack
    if event_type == "search_attempt":
        return "none"

    return "none"


df["attack_type"] = df.apply(get_attack_type, axis=1)


# -----------------------------
# 4. Keep detected attacks
# -----------------------------

attacks = df[df["attack_type"] != "none"].copy()


# -----------------------------
# 5. Daily attack activity
# -----------------------------

attacks["date"] = attacks["timestamp"].dt.date

daily_trend = (
    attacks.groupby("date")
    .size()
    .reset_index(name="attack_count")
)

daily_trend["date"] = daily_trend["date"].astype(str)


# -----------------------------
# 6. Attack type distribution
# -----------------------------

type_dist = (
    attacks["attack_type"]
    .value_counts()
    .reset_index()
)

type_dist.columns = ["attack_type", "count"]


# -----------------------------
# 7. Top attacker IPs
# -----------------------------

top_ips = (
    attacks["ip"]
    .value_counts()
    .head(10)
    .reset_index()
)

top_ips.columns = ["source_ip", "attempts"]


# -----------------------------
# 8. Endpoint risk
# -----------------------------

endpoint_totals = df.groupby("endpoint").size()

endpoint_attacks = attacks.groupby("endpoint").size()

endpoint_risk = (
    endpoint_attacks
    .div(endpoint_totals)
    .fillna(0)
    .mul(100)
    .round(1)
    .reset_index()
)

endpoint_risk.columns = ["endpoint", "attack_rate_pct"]


# -----------------------------
# 9. Severity
# -----------------------------

severity_map = {
    "brute_force": "high",
    "config_exposure": "medium",
    "api_enumeration": "medium",
    "file_upload": "high",
    "xss": "high",
    "sqli": "critical"
}

attacks["severity"] = attacks["attack_type"].map(severity_map)

severity_dist = (
    attacks["severity"]
    .value_counts()
    .reset_index()
)

severity_dist.columns = ["severity", "count"]


# -----------------------------
# 10. Hourly attack pattern
# -----------------------------

attacks["hour"] = attacks["timestamp"].dt.hour

hourly = (
    attacks.groupby("hour")
    .size()
    .reindex(range(24), fill_value=0)
    .reset_index()
)

hourly.columns = ["hour", "count"]

peak_hour = int(
    hourly.loc[hourly["count"].idxmax(), "hour"]
)


# -----------------------------
# 11. Summary
# -----------------------------

summary = {
    "total_events": int(len(df)),
    "total_attacks_detected": int(len(attacks)),
    "unique_attacker_ips": int(attacks["ip"].nunique()),

    "detection_rate_pct": round(
        (len(attacks) / len(df)) * 100, 1
    ),

    "peak_attack_hour": peak_hour,

    "most_targeted_endpoint": (
        endpoint_risk
        .sort_values("attack_rate_pct", ascending=False)
        .iloc[0]["endpoint"]
    ),

    "most_common_attack_type": (
        type_dist.iloc[0]["attack_type"]
        if not type_dist.empty
        else "none"
    ),

    "daily_trend": daily_trend.to_dict(
        orient="records"
    ),

    "type_distribution": type_dist.to_dict(
        orient="records"
    ),

    "top_ips": top_ips.to_dict(
        orient="records"
    ),

    "endpoint_risk": endpoint_risk.to_dict(
        orient="records"
    ),

    "severity_distribution": severity_dist.to_dict(
        orient="records"
    ),

    "hourly_pattern": hourly.to_dict(
        orient="records"
    )
}


# -----------------------------
# 12. Save dashboard data
# -----------------------------

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
    json.dump(summary, file, indent=2)


# -----------------------------
# 13. Print results
# -----------------------------

print("=== Honeypot Attack Analytics ===")
print(f"Total events logged:        {summary['total_events']}")
print(f"Total attacks detected:     {summary['total_attacks_detected']}")
print(f"Unique attacker IPs:        {summary['unique_attacker_ips']}")
print(f"Detection rate:             {summary['detection_rate_pct']}%")
print(f"Peak attack hour:           {summary['peak_attack_hour']}:00")
print(f"Most targeted endpoint:     {summary['most_targeted_endpoint']}")
print(f"Most common attack type:    {summary['most_common_attack_type']}")
print()
print("Saved dashboard data -> dashboard_data.json")