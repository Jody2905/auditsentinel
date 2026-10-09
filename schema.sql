-- AuditSentinel database schema
-- Written in standard SQL so it can move to PostgreSQL later with minimal changes.

-- People who are allowed to use the monitored database
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    role        TEXT    NOT NULL CHECK (role IN ('admin', 'analyst', 'clerk', 'auditor')),
    department  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tables in the monitored system that hold sensitive data
CREATE TABLE IF NOT EXISTS sensitive_tables (
    table_name   TEXT PRIMARY KEY,
    sensitivity  TEXT NOT NULL CHECK (sensitivity IN ('low', 'medium', 'high'))
);

-- Every audit log line we ingest becomes one row here
CREATE TABLE IF NOT EXISTS audit_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time     TEXT    NOT NULL,          -- ISO 8601, e.g. 2026-10-05T14:32:10
    username       TEXT    NOT NULL,
    source_ip      TEXT    NOT NULL,
    event_type     TEXT    NOT NULL CHECK (event_type IN (
                       'LOGIN_SUCCESS', 'LOGIN_FAILED',
                       'SELECT', 'INSERT', 'UPDATE', 'DELETE',
                       'GRANT', 'REVOKE')),
    target_table   TEXT,                      -- NULL for logins
    rows_affected  INTEGER DEFAULT 0,
    raw_line       TEXT    NOT NULL,          -- original log line, kept for evidence
    ingested_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes make the detection queries fast once there are many events
CREATE INDEX IF NOT EXISTS idx_events_time     ON audit_events (event_time);
CREATE INDEX IF NOT EXISTS idx_events_user     ON audit_events (username);
CREATE INDEX IF NOT EXISTS idx_events_type     ON audit_events (event_type);

-- The same log line can never be stored twice, so re-running ingestion is safe
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_raw ON audit_events (raw_line);

-- Findings produced by the detection rules
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    username     TEXT,
    source_ip    TEXT,
    description  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'closed'))
);

-- Links each alert to the events that triggered it (many-to-many)
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id  INTEGER NOT NULL REFERENCES alerts (id),
    event_id  INTEGER NOT NULL REFERENCES audit_events (id),
    PRIMARY KEY (alert_id, event_id)
);
