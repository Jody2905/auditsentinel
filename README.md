# AuditSentinel

[![tests](https://github.com/Jody2905/auditsentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/Jody2905/auditsentinel/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)

**Database audit log anomaly detector.** AuditSentinel ingests database audit logs, validates and stores them in a relational database, and runs detection rules that flag suspicious activity such as brute-force logins, data exfiltration, privilege escalation and mass deletion. Every alert is linked to the exact log events that caused it, and a web dashboard lets an analyst investigate and triage them.

The simulated environment is modelled on a government treasury system, with accounts payable, payroll and bank account data, which is the kind of system where database misuse does the most damage.

![AuditSentinel dashboard](docs/dashboard.png)

---

## What it detects

| Rule | Severity | What it looks for |
|---|---|---|
| `brute_force_login` | High / **Critical** | 10+ failed logins for one account from one IP within 5 minutes. Escalates to critical if a successful login follows. |
| `external_ip_access` | Medium / High | Any activity from an IP outside the internal network. |
| `off_hours_sensitive_access` | Medium / High | Reads or writes on sensitive tables outside 07:00 to 19:00, Monday to Friday. |
| `bulk_data_read` | High / **Critical** | A single `SELECT` returning 10,000+ rows (possible exfiltration). Critical on high-sensitivity tables. |
| `unauthorized_privilege_change` | **Critical** | `GRANT` or `REVOKE` by any account that is not an admin, including unknown accounts. |
| `mass_delete` | High | A single `DELETE` affecting 500+ rows. |

On the included sample data, AuditSentinel finds all five planted attack scenarios with **zero false positives** across more than 530 normal events.

---

## How it works

```
generate_logs.py  →  logs/audit_log.jsonl  →  ingest.py  →  SQLite database  →  detect.py  →  app.py
   (simulate)            (raw log file)        (validate)      (audit_events)      (6 rules)    (dashboard)
```

1. **Generate:** `generate_logs.py` simulates a week of database activity for seven staff across Treasury, Accounts Payable, Payroll, IT and Internal Audit, with five attack scenarios hidden in the normal traffic.
2. **Ingest:** `ingest.py` validates each log line (JSON structure, timestamp, IP address, action type, row count) before it reaches the database. Invalid lines are written to `logs/rejected.log` with the reason, so nothing is dropped silently.
3. **Detect:** `detect.py` runs each rule, saves new alerts, and records which events triggered each one.
4. **Investigate:** `app.py` serves a web dashboard to filter alerts, inspect their evidence, review a user's full activity timeline, and move alerts through open → investigating → closed.

![Alert detail with evidence and triage](docs/alert-detail.png)

### Database schema

```mermaid
erDiagram
    users {
        int id PK
        text username UK
        text role
        text department
    }
    sensitive_tables {
        text table_name PK
        text sensitivity
    }
    audit_events {
        int id PK
        text event_time
        text username
        text source_ip
        text event_type
        text target_table
        int rows_affected
        text raw_line UK
    }
    alerts {
        int id PK
        text rule_name
        text severity
        text username
        text description
        text status
    }
    alert_events {
        int alert_id FK
        int event_id FK
    }
    alerts ||--o{ alert_events : "has evidence"
    audit_events ||--o{ alert_events : "is evidence for"
    users ||..o{ audit_events : "performs"
    sensitive_tables ||..o{ audit_events : "classifies"
```

---

## Security and design decisions

- **Parameterized queries everywhere.** Log content is treated as untrusted input. Values are always passed with `?` placeholders, never formatted into SQL, so a malicious username like `'; DROP TABLE users; --` is stored as plain text. A test proves this.
- **Validate before storing.** Malformed lines, invalid IPs (such as `999.1.1.1`), unknown actions and negative row counts are rejected at the boundary.
- **No silent data loss.** Every rejected line is logged with its reason. In security monitoring, a dropped log line could be the evidence that matters.
- **Integrity enforced by the database.** `CHECK` constraints restrict roles, event types, severities and statuses, so bad values are refused even if application code has a bug.
- **Idempotent processing.** A `UNIQUE` index on the raw log line and evidence-based alert de-duplication mean ingestion and detection can be re-run safely without duplicates.
- **Atomic ingestion.** Each batch is loaded in a single transaction: all of it is saved, or none of it.
- **Traceable alerts.** The `alert_events` table links each alert to the original events, so an analyst can always trace a finding back to the source log lines.
- **Hardened dashboard.** CSRF tokens protect every state-changing form, filter and status values are whitelisted, Jinja's automatic escaping blocks XSS from log content, the server binds only to `127.0.0.1` by default, and Flask debug mode stays off.
- **Least privilege in Docker.** The container runs the app as an unprivileged user, not root.
- **Tunable thresholds.** Detection thresholds are constants at the top of `detect.py`. During testing, lowering the bulk-read threshold from 10,000 to 100 rows produced more than 140 false positives on normal activity, which shows why tuning matters.

---

## Testing

37 automated tests cover validation, ingestion, every detection rule and the dashboard's security controls. Each test runs against its own temporary database. GitHub Actions runs the full suite on Python 3.11, 3.12 and 3.13 on every push.

- **Every rule is tested both ways:** it must catch its attack, and stay quiet just below its threshold or on normal activity (for example, 9 failed logins raise nothing; 10 do).
- **Security tests:** SQL injection in a log line, an HTML `<script>` payload in a username, missing or forged CSRF tokens, and unknown status values.

The tests found a real bug during development. The original CSRF check compared the submitted token with the session token directly, so a visitor with **no session** could submit an **empty** token and `"" == ""` passed. The check now requires both tokens to be present, and a test guards against the bug returning.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

---

## Getting started

**Requirements:** Python 3.11 or newer. SQLite is built into Python; Flask is installed from `requirements.txt`.

```bash
git clone https://github.com/Jody2905/auditsentinel.git
cd auditsentinel
python -m pip install -r requirements.txt

python db.py              # create the database (answer y to start fresh)
python generate_logs.py   # create logs/audit_log.jsonl
python ingest.py          # validate and load the log
python detect.py          # run the detection rules
python app.py             # start the dashboard at http://127.0.0.1:5000
```

On Windows, use `py` instead of `python` if `python` isn't recognized.

To see input validation in action:

```bash
python ingest.py test_bad_lines.jsonl
```

This loads 1 valid line and rejects 6 malformed ones; the reasons appear in `logs/rejected.log`.

### Run with Docker

One command builds a fresh demo database and starts the dashboard:

```bash
docker build -t auditsentinel .
docker run --rm -p 127.0.0.1:5000:5000 auditsentinel
```

Then open http://127.0.0.1:5000. The `127.0.0.1:` prefix keeps the dashboard reachable only from your own computer.

---

## Project structure

```
auditsentinel/
├── schema.sql             # tables, constraints and indexes
├── db.py                  # connection helper, database setup and seed data
├── generate_logs.py       # simulated audit log with planted attacks
├── ingest.py              # validates and loads log files
├── detect.py              # detection rules and alert storage
├── app.py                 # Flask dashboard
├── templates/             # dashboard pages (alerts, alert detail, user timeline)
├── static/style.css       # dashboard styling
├── tests/                 # pytest suite (ingestion, detection, dashboard security)
├── .github/workflows/     # GitHub Actions: runs the tests on every push
├── Dockerfile
├── requirements.txt       # runtime dependencies
├── requirements-dev.txt   # adds pytest
└── test_bad_lines.jsonl   # malformed lines for trying out validation
```

---

## Roadmap

- [x] Phase 1: Schema design and simulated audit logs
- [x] Phase 2: Validated, idempotent ingestion
- [x] Phase 3: Detection engine with six rules and linked evidence
- [x] Phase 4: Flask dashboard to view, filter and triage alerts
- [x] Phase 5: Test suite, GitHub Actions CI and Docker

**Future ideas**
- PostgreSQL support alongside SQLite
- Per-user baselines, flagging activity that is unusual *for that person* rather than using fixed thresholds
- Ingesting real SQL Server audit or PostgreSQL `pgaudit` logs
- Analyst notes on alerts, and login for the dashboard itself

---

## Author

**Jody-Ann Trimmingham**, B.S. Computer Networks and Cybersecurity
GitHub: [@Jody2905](https://github.com/Jody2905)
