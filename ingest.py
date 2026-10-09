"""Load audit log lines into the database.

Every line is validated before it touches the database. Bad lines are not
silently dropped: they are written to logs/rejected.log with the reason, so
nothing disappears without a trace.

Run:
    python ingest.py                      (uses logs/audit_log.jsonl)
    python ingest.py path/to/other.jsonl  (any other log file)
"""

import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

from db import get_connection

DEFAULT_LOG = Path(__file__).parent / "logs" / "audit_log.jsonl"
REJECTED_LOG = Path(__file__).parent / "logs" / "rejected.log"

VALID_ACTIONS = {
    "LOGIN_SUCCESS", "LOGIN_FAILED",
    "SELECT", "INSERT", "UPDATE", "DELETE",
    "GRANT", "REVOKE",
}
LOGIN_ACTIONS = {"LOGIN_SUCCESS", "LOGIN_FAILED"}
REQUIRED_FIELDS = ("timestamp", "user", "ip", "action")


class ValidationError(Exception):
    """Raised when a log line is missing data or has a bad value."""


def parse_line(line):
    """Turn one raw log line into a clean dict, or raise ValidationError."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        raise ValidationError("not valid JSON")

    if not isinstance(data, dict):
        raise ValidationError("line is not a JSON object")

    for field in REQUIRED_FIELDS:
        if not data.get(field):
            raise ValidationError(f"missing field '{field}'")

    # Timestamp must be a real date in ISO format
    try:
        event_time = datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        raise ValidationError(f"bad timestamp '{data['timestamp']}'")

    # The ipaddress module rejects things like 999.1.1.1 or 'hello'
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
    except ValueError:
        raise ValidationError(f"bad IP address '{data['ip']}'")

    action = str(data["action"]).upper()
    if action not in VALID_ACTIONS:
        raise ValidationError(f"unknown action '{data['action']}'")

    table = data.get("table")
    if action not in LOGIN_ACTIONS and not table:
        raise ValidationError(f"{action} event has no table")

    rows = data.get("rows", 0)
    if not isinstance(rows, int) or isinstance(rows, bool) or rows < 0:
        raise ValidationError(f"bad row count '{rows}'")

    return {
        "event_time": event_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "username": str(data["user"]).strip().lower(),
        "source_ip": ip,
        "event_type": action,
        "target_table": table,
        "rows_affected": rows,
        "raw_line": line,
    }


def ingest(log_path):
    """Read a log file and insert every valid line. Returns a summary dict."""
    summary = {"read": 0, "inserted": 0, "duplicates": 0, "rejected": 0}
    rejected = []
    valid_events = []

    with open(log_path, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            summary["read"] += 1
            try:
                valid_events.append(parse_line(line))
            except ValidationError as err:
                summary["rejected"] += 1
                rejected.append(f"line {line_number}: {err} | {line}")

    conn = get_connection()
    with conn:  # one transaction: either the whole batch goes in, or none of it
        for e in valid_events:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO audit_events
                    (event_time, username, source_ip, event_type,
                     target_table, rows_affected, raw_line)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (e["event_time"], e["username"], e["source_ip"], e["event_type"],
                 e["target_table"], e["rows_affected"], e["raw_line"]),
            )
            # rowcount is 0 when the unique index blocked a duplicate
            if cursor.rowcount == 1:
                summary["inserted"] += 1
            else:
                summary["duplicates"] += 1
    conn.close()

    if rejected:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(REJECTED_LOG, "a", encoding="utf-8") as f:
            for entry in rejected:
                f.write(f"[{stamp}] {log_path} {entry}\n")

    return summary


def main():
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOG
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        print("Run 'python generate_logs.py' first.")
        sys.exit(1)

    summary = ingest(log_path)
    print(f"Ingested {log_path.name}")
    print(f"  Lines read:   {summary['read']}")
    print(f"  Inserted:     {summary['inserted']}")
    print(f"  Duplicates:   {summary['duplicates']} (already in the database, skipped)")
    print(f"  Rejected:     {summary['rejected']}", end="")
    print(f" (see {REJECTED_LOG})" if summary["rejected"] else "")


if __name__ == "__main__":
    main()
