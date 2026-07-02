"""
SentinelMind – Security Log Analysis API
=========================================
FastAPI backend that loads security logs from a CSV file, applies
rule-based threat detection, and exposes the results via REST endpoints.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_PATH = Path(__file__).parent / "data" / "sample_logs.csv"

# Hours considered "off-hours" (inclusive on both ends)
OFF_HOURS_START = 0
OFF_HOURS_END = 5

# Minimum failed-login attempts before brute-force is flagged
BRUTE_FORCE_THRESHOLD = 3

# Business-hours window used for "normal" logins
BIZ_HOURS_START = 8
BIZ_HOURS_END = 18

app = FastAPI(
    title="SentinelMind",
    description="Security log analysis and threat detection API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Data layer
# ---------------------------------------------------------------------------

def load_logs() -> pd.DataFrame:
    """Load and parse the security log CSV into a typed DataFrame."""
    df = pd.read_csv(DATA_PATH, parse_dates=["timestamp"])
    # Ensure the 'hour' column is always numeric even if CSV omits it
    if "hour" not in df.columns:
        df["hour"] = df["timestamp"].dt.hour
    else:
        df["hour"] = df["hour"].astype(int)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Explanation generator
# ---------------------------------------------------------------------------

_MITRE_MAP: dict[str, dict[str, str]] = {
    "brute_force": {
        "technique": "T1110",
        "name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "off_hours_access": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "privilege_escalation_sensitive": {
        "technique": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
}


def generate_explanation(
    threat_type: str,
    username: str,
    source_ip: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, str]:
    """
    Build human-readable and technical explanations for a detected threat,
    plus a MITRE ATT&CK tag and a recommended remediation action.
    """
    extra = extra or {}
    mitre = _MITRE_MAP.get(threat_type, {"technique": "T0000", "name": "Unknown", "url": ""})

    if threat_type == "brute_force":
        failed_count = extra.get("failed_count", BRUTE_FORCE_THRESHOLD)
        technical = (
            f"{failed_count} consecutive failed login attempts from {source_ip} "
            f"targeting '{username}' were followed by a successful authentication, "
            f"indicating a successful brute-force attack."
        )
        simple = (
            f"Someone tried the wrong password {failed_count} times from "
            f"{source_ip} and eventually broke in as '{username}'."
        )
        action = (
            "Immediately reset credentials for the affected account, "
            "block or rate-limit the source IP, and enable MFA."
        )

    elif threat_type == "off_hours_access":
        event_type = extra.get("event_type", "login")
        hour = extra.get("hour", "N/A")
        is_priv = extra.get("has_privilege_escalation", False)
        technical = (
            f"Sensitive activity ('{event_type}') detected for '{username}' "
            f"from {source_ip} at hour {hour:02d}:xx, which falls outside normal "
            f"business hours ({OFF_HOURS_START:02d}:00–{OFF_HOURS_END:02d}:59)."
        )
        if is_priv:
            technical += " The session also included privilege escalation, elevating the risk."
        simple = (
            f"'{username}' was active at an unusual time (hour {hour}) "
            f"from {source_ip}. This kind of after-hours activity can be a sign "
            f"of an intruder or insider threat."
        )
        action = (
            "Review the user's activity log for this session, verify with the "
            "account owner, and consider enforcing time-based access controls."
        )

    elif threat_type == "privilege_escalation_sensitive":
        technical = (
            f"Account '{username}' from {source_ip} performed privilege escalation "
            f"immediately followed by access to sensitive data. This two-step pattern "
            f"is a strong indicator of lateral movement or data exfiltration."
        )
        simple = (
            f"'{username}' upgraded their own permissions and then accessed "
            f"confidential data from {source_ip}. This is a classic sign of an "
            f"account being misused or compromised."
        )
        action = (
            "Suspend the account pending investigation, audit all data accessed, "
            "and review how privilege escalation was permitted."
        )

    else:
        technical = f"Unclassified threat detected for '{username}' from {source_ip}."
        simple = technical
        action = "Investigate manually."

    return {
        "technical_explanation": technical,
        "simple_explanation": simple,
        "mitre_technique": mitre["technique"],
        "mitre_name": mitre["name"],
        "mitre_url": mitre["url"],
        "recommended_action": action,
    }


# ---------------------------------------------------------------------------
# Threat detection engine
# ---------------------------------------------------------------------------

def _severity_from_score(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def detect_threats(df: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Apply all detection rules to the log DataFrame and return a list of
    threat dictionaries, one per (username, source_ip, threat_type) group.

    Rules
    -----
    1. Brute force            – ≥3 failed logins from same IP followed by success  → HIGH
    2. Off-hours access       – suspicious events between 00:00–05:59
                                  base score MEDIUM; HIGH when privilege_escalation involved
    3. Privilege escalation   – privilege_escalation followed by access_sensitive_data → HIGH
    4. Normal business login  – success login 08:00-18:00 → LOW / suppressed
    """
    alerts: list[dict[str, Any]] = []
    # Track which (username, ip) pairs have already been flagged so we can
    # avoid emitting duplicate off-hours alerts for the same session.
    flagged_offhours: set[tuple[str, str]] = set()

    # ── Rule 1: Brute force ─────────────────────────────────────────────────
    for (username, source_ip), group in df.groupby(["username", "source_ip"]):
        group = group.sort_values("timestamp")
        failed = group[group["status"] == "failed"]
        success = group[group["status"] == "success"]

        if len(failed) >= BRUTE_FORCE_THRESHOLD and not success.empty:
            # At least one success after the failures
            last_fail_time = failed["timestamp"].max()
            post_fail_success = success[success["timestamp"] > last_fail_time]
            if not post_fail_success.empty:
                score = min(60 + len(failed) * 5, 95)  # 75–95 depending on volume
                extra = {"failed_count": len(failed)}
                explanation = generate_explanation(
                    "brute_force", username, source_ip, extra
                )
                alerts.append(
                    {
                        "threat_type": "brute_force",
                        "username": username,
                        "source_ip": source_ip,
                        "risk_score": score,
                        "severity": _severity_from_score(score),
                        "first_seen": group["timestamp"].min().isoformat(),
                        "last_seen": group["timestamp"].max().isoformat(),
                        "event_count": len(group),
                        **explanation,
                    }
                )

    # ── Rule 3: Privilege escalation → sensitive data access ────────────────
    # (evaluated before off-hours so we can mark the pair as already escalated)
    escalated_pairs: set[tuple[str, str]] = set()
    for (username, source_ip), group in df.groupby(["username", "source_ip"]):
        group = group.sort_values("timestamp")
        priv_events = group[group["event_type"] == "privilege_escalation"]
        sens_events = group[group["event_type"] == "access_sensitive_data"]

        if not priv_events.empty and not sens_events.empty:
            last_priv = priv_events["timestamp"].max()
            post_priv_sens = sens_events[sens_events["timestamp"] > last_priv]
            if not post_priv_sens.empty:
                escalated_pairs.add((username, source_ip))
                score = 90
                explanation = generate_explanation(
                    "privilege_escalation_sensitive", username, source_ip
                )
                alerts.append(
                    {
                        "threat_type": "privilege_escalation_sensitive",
                        "username": username,
                        "source_ip": source_ip,
                        "risk_score": score,
                        "severity": _severity_from_score(score),
                        "first_seen": group["timestamp"].min().isoformat(),
                        "last_seen": group["timestamp"].max().isoformat(),
                        "event_count": len(group),
                        **explanation,
                    }
                )

    # ── Rule 2: Off-hours access ─────────────────────────────────────────────
    off_hours_events = df[
        (df["hour"] >= OFF_HOURS_START) & (df["hour"] <= OFF_HOURS_END)
    ]
    suspicious_types = {"login", "privilege_escalation", "access_sensitive_data"}

    for (username, source_ip), group in off_hours_events.groupby(
        ["username", "source_ip"]
    ):
        relevant = group[group["event_type"].isin(suspicious_types)]
        if relevant.empty:
            continue

        key = (username, source_ip)
        if key in flagged_offhours:
            continue
        flagged_offhours.add(key)

        has_priv_esc = "privilege_escalation" in relevant["event_type"].values
        # If privilege_escalation_sensitive already fired for this pair the
        # off-hours component is captured there; still emit separately so the
        # analyst sees both threat dimensions.
        base_score = 75 if has_priv_esc else 55
        representative = relevant.iloc[0]
        extra = {
            "event_type": representative["event_type"],
            "hour": int(representative["hour"]),
            "has_privilege_escalation": has_priv_esc,
        }
        explanation = generate_explanation(
            "off_hours_access", username, source_ip, extra
        )
        alerts.append(
            {
                "threat_type": "off_hours_access",
                "username": username,
                "source_ip": source_ip,
                "risk_score": base_score,
                "severity": _severity_from_score(base_score),
                "first_seen": group["timestamp"].min().isoformat(),
                "last_seen": group["timestamp"].max().isoformat(),
                "event_count": len(group),
                **explanation,
            }
        )

    # Sort by risk score descending before returning
    alerts.sort(key=lambda a: a["risk_score"], reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/alerts", summary="Return all detected threat alerts")
def get_alerts() -> list[dict[str, Any]]:
    """
    Runs the full threat-detection pipeline against the loaded logs and
    returns every alert sorted by **risk_score** descending.
    """
    df = load_logs()
    return detect_threats(df)


@app.get("/alerts/{username}", summary="Return event timeline for a specific user")
def get_user_timeline(username: str) -> dict[str, Any]:
    """
    Returns a chronological event timeline for *username* together with
    any alerts that involve that user — useful for the 'Attack Story' view.
    """
    df = load_logs()
    user_df = df[df["username"] == username]
    if user_df.empty:
        raise HTTPException(status_code=404, detail=f"No events found for user '{username}'")

    # Build timeline events
    timeline = []
    for _, row in user_df.iterrows():
        timeline.append(
            {
                "timestamp": row["timestamp"].isoformat(),
                "event_type": row["event_type"],
                "source_ip": row["source_ip"],
                "status": row["status"],
                "hour": int(row["hour"]),
            }
        )

    # Collect only the alerts relevant to this user
    all_alerts = detect_threats(df)
    user_alerts = [a for a in all_alerts if a["username"] == username]

    return {
        "username": username,
        "total_events": len(timeline),
        "timeline": timeline,
        "alerts": user_alerts,
    }


@app.get("/stats", summary="Return summary statistics for the current log dataset")
def get_stats() -> dict[str, Any]:
    """
    Returns high-level statistics: total event count, alert breakdown by
    severity, and per-threat-type counts.
    """
    df = load_logs()
    alerts = detect_threats(df)

    severity_counts: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    threat_type_counts: dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert["severity"]] = (
            severity_counts.get(alert["severity"], 0) + 1
        )
        threat_type_counts[alert["threat_type"]] = (
            threat_type_counts.get(alert["threat_type"], 0) + 1
        )

    return {
        "total_events": len(df),
        "total_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "threat_type_breakdown": threat_type_counts,
        "unique_users": int(df["username"].nunique()),
        "unique_ips": int(df["source_ip"].nunique()),
    }


# ---------------------------------------------------------------------------
# Entry point (development)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
