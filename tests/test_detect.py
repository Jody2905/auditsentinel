"""Tests for the detection rules.

Every rule is tested both ways: it must catch its attack (no false negatives)
and stay quiet on normal activity (no false positives).
"""

from datetime import datetime, timedelta

import db
import detect
from conftest import write_log
from ingest import ingest


def run_detection():
    detect.main()
    conn = db.get_connection()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    conn.close()
    return alerts


def rules_fired(alerts):
    return sorted(a["rule_name"] for a in alerts)


def event(time, user, ip, action, table=None, rows=0):
    return {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "user": user,
            "ip": ip, "action": action, "table": table, "rows": rows}


TUESDAY_10AM = datetime(2026, 10, 6, 10, 0, 0)


def test_normal_activity_raises_no_alerts(normal_log):
    ingest(normal_log)
    assert run_detection() == []


def test_full_log_catches_all_five_attacks(full_log):
    ingest(full_log)
    alerts = run_detection()
    assert rules_fired(alerts) == [
        "brute_force_login",
        "bulk_data_read",
        "external_ip_access",
        "mass_delete",
        "off_hours_sensitive_access",
        "unauthorized_privilege_change",
    ]
    by_rule = {a["rule_name"]: a for a in alerts}
    assert by_rule["brute_force_login"]["username"] == "kbaptiste"
    assert by_rule["bulk_data_read"]["username"] == "rcharles"
    assert by_rule["unauthorized_privilege_change"]["username"] == "sdaniel"
    assert by_rule["off_hours_sensitive_access"]["username"] == "tlewis"
    assert by_rule["mass_delete"]["username"] == "pjohn"


def test_running_detection_twice_creates_no_duplicate_alerts(full_log):
    ingest(full_log)
    first = run_detection()
    second = run_detection()
    assert len(second) == len(first)


def test_every_alert_has_linked_evidence(full_log):
    ingest(full_log)
    run_detection()
    conn = db.get_connection()
    orphans = conn.execute(
        """
        SELECT COUNT(*) FROM alerts a
        WHERE NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.alert_id = a.id)
        """
    ).fetchone()[0]
    conn.close()
    assert orphans == 0


# ---- Brute force -------------------------------------------------------------

def failed_logins(count, start=TUESDAY_10AM, gap_seconds=5):
    return [event(start + timedelta(seconds=i * gap_seconds), "kbaptiste",
                  "10.20.1.11", "LOGIN_FAILED") for i in range(count)]


def test_brute_force_below_threshold_is_ignored(temp_db):
    events = failed_logins(detect.BRUTE_FORCE_FAILURES - 1)
    ingest(write_log(temp_db / "log.jsonl", events))
    assert run_detection() == []


def test_brute_force_without_success_is_high(temp_db):
    events = failed_logins(detect.BRUTE_FORCE_FAILURES)
    ingest(write_log(temp_db / "log.jsonl", events))
    alerts = run_detection()
    assert rules_fired(alerts) == ["brute_force_login"]
    assert alerts[0]["severity"] == "high"


def test_brute_force_followed_by_success_is_critical(temp_db):
    events = failed_logins(detect.BRUTE_FORCE_FAILURES)
    events.append(event(TUESDAY_10AM + timedelta(minutes=2), "kbaptiste",
                        "10.20.1.11", "LOGIN_SUCCESS"))
    ingest(write_log(temp_db / "log.jsonl", events))
    alerts = run_detection()
    assert alerts[0]["severity"] == "critical"


def test_slow_failures_outside_window_are_ignored(temp_db):
    # Same number of failures, but spread over hours, not minutes
    events = failed_logins(detect.BRUTE_FORCE_FAILURES, gap_seconds=600)
    ingest(write_log(temp_db / "log.jsonl", events))
    assert run_detection() == []


# ---- Other rules -------------------------------------------------------------

def test_bulk_read_threshold(temp_db):
    events = [
        event(TUESDAY_10AM, "rcharles", "10.20.1.13", "SELECT", "payroll",
              detect.BULK_READ_ROWS - 1),
        event(TUESDAY_10AM + timedelta(minutes=1), "rcharles", "10.20.1.13",
              "SELECT", "payroll", detect.BULK_READ_ROWS),
    ]
    ingest(write_log(temp_db / "log.jsonl", events))
    alerts = run_detection()
    assert rules_fired(alerts) == ["bulk_data_read"]   # only the second one
    assert alerts[0]["severity"] == "critical"         # payroll is high sensitivity


def test_admin_grant_is_allowed_but_non_admin_is_not(temp_db):
    events = [
        event(TUESDAY_10AM, "mjames", "10.20.1.10", "GRANT", "budget_lines"),
        event(TUESDAY_10AM, "kbaptiste", "10.20.1.11", "GRANT", "budget_lines"),
    ]
    ingest(write_log(temp_db / "log.jsonl", events))
    alerts = run_detection()
    assert [a["username"] for a in alerts] == ["kbaptiste"]


def test_unknown_account_changing_permissions_is_caught(temp_db):
    events = [event(TUESDAY_10AM, "ghost", "10.20.1.99", "REVOKE", "payroll")]
    ingest(write_log(temp_db / "log.jsonl", events))
    alerts = run_detection()
    assert rules_fired(alerts) == ["unauthorized_privilege_change"]
    assert "UNKNOWN ACCOUNT" in alerts[0]["description"]


def test_weekend_access_to_sensitive_table_is_flagged(temp_db):
    saturday_noon = datetime(2026, 10, 10, 12, 0, 0)
    events = [event(saturday_noon, "agreene", "10.20.1.16", "SELECT", "payroll", 5)]
    ingest(write_log(temp_db / "log.jsonl", events))
    assert rules_fired(run_detection()) == ["off_hours_sensitive_access"]


def test_off_hours_access_to_low_sensitivity_table_is_ignored(temp_db):
    late = datetime(2026, 10, 6, 22, 0, 0)
    events = [event(late, "mjames", "10.20.1.10", "SELECT", "departments", 5)]
    ingest(write_log(temp_db / "log.jsonl", events))
    assert run_detection() == []


def test_small_delete_is_ignored_but_mass_delete_is_caught(temp_db):
    events = [
        event(TUESDAY_10AM, "pjohn", "10.20.1.15", "DELETE", "purchase_orders", 3),
        event(TUESDAY_10AM, "pjohn", "10.20.1.15", "DELETE", "purchase_orders",
              detect.MASS_DELETE_ROWS),
    ]
    ingest(write_log(temp_db / "log.jsonl", events))
    assert rules_fired(run_detection()) == ["mass_delete"]
