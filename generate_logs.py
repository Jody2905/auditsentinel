"""Generate a realistic audit log file with hidden attacks mixed in.

Real database audit logs aren't something we can share publicly, so we simulate
one. Normal activity happens during business hours; the attacks are scenarios a
detector should catch.

Run:
    python generate_logs.py
Output:
    logs/audit_log.jsonl   (one JSON object per line)
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from db import SEED_USERS

random.seed(42)  # same "random" log every run, so results are reproducible

OUTPUT = Path(__file__).parent / "logs" / "audit_log.jsonl"
START_DAY = datetime(2026, 10, 5)  # a Monday
DAYS = 5

# Each user normally works from one office IP
USER_IPS = {u[0]: f"10.20.1.{10 + i}" for i, u in enumerate(SEED_USERS)}

# Which tables each role normally touches
ROLE_TABLES = {
    "admin":   ["departments", "budget_lines"],
    "analyst": ["budget_lines", "vendor_payments", "purchase_orders"],
    "clerk":   ["purchase_orders", "vendor_payments"],
    "auditor": ["budget_lines", "vendor_payments", "purchase_orders", "payroll"],
}
ROLE_ACTIONS = {
    "admin":   ["SELECT", "UPDATE"],
    "analyst": ["SELECT", "SELECT", "SELECT", "UPDATE"],
    "clerk":   ["SELECT", "INSERT", "UPDATE"],
    "auditor": ["SELECT"],
}


def event(time, user, ip, event_type, table=None, rows=0):
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "user": user,
        "ip": ip,
        "action": event_type,
        "table": table,
        "rows": rows,
    }


def normal_activity():
    """Business-hours work: log in, run a handful of queries."""
    events = []
    for day in range(DAYS):
        date = START_DAY + timedelta(days=day)
        for username, role, _dept in SEED_USERS:
            ip = USER_IPS[username]
            t = date.replace(hour=8, minute=random.randint(0, 45), second=random.randint(0, 59))
            if random.random() < 0.1:  # people mistype passwords sometimes
                events.append(event(t, username, ip, "LOGIN_FAILED"))
                t += timedelta(seconds=random.randint(5, 30))
            events.append(event(t, username, ip, "LOGIN_SUCCESS"))

            for _ in range(random.randint(8, 20)):
                t += timedelta(minutes=random.randint(5, 30))
                if t.hour >= 17:
                    break
                action = random.choice(ROLE_ACTIONS[role])
                table = random.choice(ROLE_TABLES[role])
                rows = random.randint(1, 200) if action == "SELECT" else random.randint(1, 5)
                events.append(event(t, username, ip, action, table, rows))
    return events


def attack_scenarios():
    """The suspicious activity the detector should find. Each one is a rule we'll write."""
    events = []

    # 1. Brute force: many failed logins from an unknown IP, then a success
    t = START_DAY + timedelta(days=1, hours=2, minutes=13)
    for _ in range(25):
        events.append(event(t, "kbaptiste", "185.220.101.47", "LOGIN_FAILED"))
        t += timedelta(seconds=random.randint(1, 4))
    events.append(event(t, "kbaptiste", "185.220.101.47", "LOGIN_SUCCESS"))

    # 2. Off-hours access to a high-sensitivity table
    t = START_DAY + timedelta(days=2, hours=23, minutes=41)
    events.append(event(t, "tlewis", USER_IPS["tlewis"], "LOGIN_SUCCESS"))
    events.append(event(t + timedelta(minutes=2), "tlewis", USER_IPS["tlewis"],
                        "SELECT", "bank_accounts", 340))

    # 3. Bulk data pull (possible exfiltration) from payroll
    t = START_DAY + timedelta(days=3, hours=15, minutes=5)
    events.append(event(t, "rcharles", USER_IPS["rcharles"], "SELECT", "payroll", 48210))

    # 4. Privilege escalation: a non-admin granting permissions
    t = START_DAY + timedelta(days=3, hours=16, minutes=22)
    events.append(event(t, "sdaniel", USER_IPS["sdaniel"], "GRANT", "vendor_payments"))

    # 5. Mass deletion
    t = START_DAY + timedelta(days=4, hours=11, minutes=50)
    events.append(event(t, "pjohn", USER_IPS["pjohn"], "DELETE", "vendor_payments", 1520))

    return events


def main():
    events = normal_activity() + attack_scenarios()
    events.sort(key=lambda e: e["timestamp"])

    OUTPUT.parent.mkdir(exist_ok=True)
    with OUTPUT.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"Wrote {len(events)} events to {OUTPUT}")


if __name__ == "__main__":
    main()
