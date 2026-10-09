"""Run detection rules over the audit events and record alerts.

Each rule is a small function that looks for one kind of suspicious behaviour
and returns a list of Findings. main() runs every rule, saves new alerts, and
links each alert to the exact events that caused it (the evidence).

Run:
    python detect.py
Running it again is safe: an alert is only created once for the same evidence.
"""

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from db import get_connection

# ---------------------------------------------------------------------------
# Thresholds. Tuning these is a real part of detection work: too low and you
# drown in false alarms, too high and you miss attacks.
# ---------------------------------------------------------------------------
BRUTE_FORCE_FAILURES = 10            # failed logins...
BRUTE_FORCE_WINDOW = timedelta(minutes=5)  # ...within this time
BULK_READ_ROWS = 10_000             # a SELECT returning this many rows is unusual
MASS_DELETE_ROWS = 500               # a DELETE touching this many rows is unusual
WORK_START_HOUR = 7                  # business hours are 07:00 to 19:00, Mon-Fri
WORK_END_HOUR = 19


@dataclass
class Finding:
    rule_name: str
    severity: str
    username: str
    source_ip: str
    description: str
    event_ids: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule 1: Brute force (Python sliding window, like your Log Analyzer)
# ---------------------------------------------------------------------------
def rule_brute_force(conn):
    rows = conn.execute(
        """
        SELECT id, event_time, username, source_ip, event_type
        FROM audit_events
        WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_SUCCESS')
        ORDER BY event_time
        """
    ).fetchall()

    # Group login attempts by (user, ip) so one attacker = one alert
    attempts = defaultdict(list)
    for r in rows:
        attempts[(r["username"], r["source_ip"])].append(r)

    findings = []
    for (username, ip), events in attempts.items():
        failures = [e for e in events if e["event_type"] == "LOGIN_FAILED"]
        window = []
        burst = None
        for e in failures:
            t = datetime.fromisoformat(e["event_time"])
            window.append((t, e))
            # drop failures that are older than the window
            window = [(wt, we) for wt, we in window if t - wt <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_FAILURES:
                burst = window
        if not burst:
            continue

        # Did the attacker get in? Look for a success right after the burst.
        last_fail_time = burst[-1][0]
        success = next(
            (e for e in events
             if e["event_type"] == "LOGIN_SUCCESS"
             and timedelta(0) <= datetime.fromisoformat(e["event_time"]) - last_fail_time
             <= BRUTE_FORCE_WINDOW),
            None,
        )
        all_failures_in_burst = [
            e for e in failures
            if burst[0][0] <= datetime.fromisoformat(e["event_time"]) <= last_fail_time
        ]
        event_ids = [e["id"] for e in all_failures_in_burst]

        if success:
            event_ids.append(success["id"])
            severity = "critical"
            outcome = "followed by a SUCCESSFUL login - account likely compromised"
        else:
            severity = "high"
            outcome = "no successful login followed"

        findings.append(Finding(
            "brute_force_login", severity, username, ip,
            f"{len(all_failures_in_burst)} failed logins for '{username}' from {ip} "
            f"within {int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes, {outcome}.",
            event_ids,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule 2: Access from outside the internal network
# ---------------------------------------------------------------------------
def rule_external_ip(conn):
    rows = conn.execute(
        "SELECT id, username, source_ip, event_type FROM audit_events"
    ).fetchall()

    grouped = defaultdict(list)
    for r in rows:
        if not ipaddress.ip_address(r["source_ip"]).is_private:
            grouped[(r["username"], r["source_ip"])].append(r)

    findings = []
    for (username, ip), events in grouped.items():
        got_in = any(e["event_type"] == "LOGIN_SUCCESS" for e in events)
        findings.append(Finding(
            "external_ip_access", "high" if got_in else "medium", username, ip,
            f"'{username}' had {len(events)} event(s) from external IP {ip}"
            + (" including a successful login." if got_in else "."),
            [e["id"] for e in events],
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule 3: Sensitive data touched outside business hours (SQL with a JOIN)
# ---------------------------------------------------------------------------
def rule_off_hours_sensitive(conn):
    rows = conn.execute(
        """
        SELECT e.id, e.event_time, e.username, e.source_ip, e.event_type,
               e.target_table, e.rows_affected, s.sensitivity
        FROM audit_events e
        JOIN sensitive_tables s ON s.table_name = e.target_table
        WHERE s.sensitivity IN ('medium', 'high')
          AND (
                CAST(strftime('%H', e.event_time) AS INTEGER) < ?
             OR CAST(strftime('%H', e.event_time) AS INTEGER) >= ?
             OR strftime('%w', e.event_time) IN ('0', '6')   -- Sunday, Saturday
          )
        """,
        (WORK_START_HOUR, WORK_END_HOUR),
    ).fetchall()

    return [
        Finding(
            "off_hours_sensitive_access",
            "high" if r["sensitivity"] == "high" else "medium",
            r["username"], r["source_ip"],
            f"'{r['username']}' ran {r['event_type']} on {r['sensitivity']}-sensitivity "
            f"table '{r['target_table']}' at {r['event_time']} (outside business hours).",
            [r["id"]],
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Rule 4: Bulk data read, possible exfiltration
# ---------------------------------------------------------------------------
def rule_bulk_read(conn):
    rows = conn.execute(
        """
        SELECT e.id, e.event_time, e.username, e.source_ip, e.target_table,
               e.rows_affected, COALESCE(s.sensitivity, 'low') AS sensitivity
        FROM audit_events e
        LEFT JOIN sensitive_tables s ON s.table_name = e.target_table
        WHERE e.event_type = 'SELECT' AND e.rows_affected >= ?
        """,
        (BULK_READ_ROWS,),
    ).fetchall()

    return [
        Finding(
            "bulk_data_read",
            "critical" if r["sensitivity"] == "high" else "high",
            r["username"], r["source_ip"],
            f"'{r['username']}' read {r['rows_affected']:,} rows from "
            f"'{r['target_table']}' ({r['sensitivity']} sensitivity) at {r['event_time']}.",
            [r["id"]],
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Rule 5: Permission changes by someone who isn't an admin
# ---------------------------------------------------------------------------
def rule_privilege_change(conn):
    # LEFT JOIN so accounts missing from the users table are caught too
    rows = conn.execute(
        """
        SELECT e.id, e.event_time, e.username, e.source_ip, e.event_type,
               e.target_table, u.role
        FROM audit_events e
        LEFT JOIN users u ON u.username = e.username
        WHERE e.event_type IN ('GRANT', 'REVOKE')
          AND (u.role IS NULL OR u.role <> 'admin')
        """
    ).fetchall()

    return [
        Finding(
            "unauthorized_privilege_change", "critical",
            r["username"], r["source_ip"],
            f"'{r['username']}' (role: {r['role'] or 'UNKNOWN ACCOUNT'}) ran "
            f"{r['event_type']} on '{r['target_table']}' at {r['event_time']}. "
            f"Only admins should change permissions.",
            [r["id"]],
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Rule 6: Mass deletion
# ---------------------------------------------------------------------------
def rule_mass_delete(conn):
    rows = conn.execute(
        """
        SELECT id, event_time, username, source_ip, target_table, rows_affected
        FROM audit_events
        WHERE event_type = 'DELETE' AND rows_affected >= ?
        """,
        (MASS_DELETE_ROWS,),
    ).fetchall()

    return [
        Finding(
            "mass_delete", "high", r["username"], r["source_ip"],
            f"'{r['username']}' deleted {r['rows_affected']:,} rows from "
            f"'{r['target_table']}' at {r['event_time']}.",
            [r["id"]],
        )
        for r in rows
    ]


RULES = [
    rule_brute_force,
    rule_external_ip,
    rule_off_hours_sensitive,
    rule_bulk_read,
    rule_privilege_change,
    rule_mass_delete,
]


def already_alerted(conn, finding):
    """True if this rule has already raised an alert for any of these events."""
    placeholders = ",".join("?" * len(finding.event_ids))
    row = conn.execute(
        f"""
        SELECT 1 FROM alerts a
        JOIN alert_events ae ON ae.alert_id = a.id
        WHERE a.rule_name = ? AND ae.event_id IN ({placeholders})
        LIMIT 1
        """,
        (finding.rule_name, *finding.event_ids),
    ).fetchone()
    return row is not None


def save_finding(conn, finding):
    cursor = conn.execute(
        """
        INSERT INTO alerts (rule_name, severity, username, source_ip, description)
        VALUES (?, ?, ?, ?, ?)
        """,
        (finding.rule_name, finding.severity, finding.username,
         finding.source_ip, finding.description),
    )
    alert_id = cursor.lastrowid
    conn.executemany(
        "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
        [(alert_id, event_id) for event_id in finding.event_ids],
    )


def main():
    conn = get_connection()
    new_count = 0
    with conn:
        for rule in RULES:
            for finding in rule(conn):
                if not already_alerted(conn, finding):
                    save_finding(conn, finding)
                    new_count += 1

    print(f"Detection complete: {new_count} new alert(s).\n")

    severity_order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
                     "WHEN 'medium' THEN 2 ELSE 3 END"
    alerts = conn.execute(
        f"""
        SELECT a.id, a.severity, a.rule_name, a.description,
               COUNT(ae.event_id) AS evidence
        FROM alerts a
        JOIN alert_events ae ON ae.alert_id = a.id
        WHERE a.status = 'open'
        GROUP BY a.id
        ORDER BY {severity_order}, a.id
        """
    ).fetchall()

    print(f"Open alerts: {len(alerts)}")
    print("-" * 70)
    for a in alerts:
        print(f"#{a['id']:<3} [{a['severity'].upper():<8}] {a['rule_name']}")
        print(f"      {a['description']}")
        print(f"      Evidence: {a['evidence']} event(s)\n")
    conn.close()


if __name__ == "__main__":
    main()
