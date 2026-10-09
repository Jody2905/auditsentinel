"""Database helpers for AuditSentinel.

Run this file directly to create (or reset) the database:
    python db.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "auditsentinel.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Sample users and sensitive tables for the simulated Treasury-style system
SEED_USERS = [
    ("mjames",   "admin",   "IT"),
    ("kbaptiste", "analyst", "Treasury"),
    ("sdaniel",  "analyst", "Treasury"),
    ("rcharles", "clerk",   "Accounts Payable"),
    ("tlewis",   "clerk",   "Accounts Payable"),
    ("pjohn",    "clerk",   "Payroll"),
    ("agreene",  "auditor", "Internal Audit"),
]

SEED_SENSITIVE_TABLES = [
    ("payroll",          "high"),
    ("vendor_payments",  "high"),
    ("bank_accounts",    "high"),
    ("budget_lines",     "medium"),
    ("purchase_orders",  "medium"),
    ("departments",      "low"),
]


def get_connection():
    """Open a connection with foreign keys enforced and rows usable like dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(reset=False):
    """Create all tables from schema.sql and load the seed data."""
    if reset and DB_PATH.exists():
        DB_PATH.unlink()

    conn = get_connection()
    with conn:  # commits automatically, rolls back on error
        conn.executescript(SCHEMA_PATH.read_text())

        # INSERT OR IGNORE so running this twice doesn't create duplicates.
        # The ? placeholders are parameterized queries: never build SQL with
        # string formatting, or you open yourself to SQL injection.
        conn.executemany(
            "INSERT OR IGNORE INTO users (username, role, department) VALUES (?, ?, ?)",
            SEED_USERS,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO sensitive_tables (table_name, sensitivity) VALUES (?, ?)",
            SEED_SENSITIVE_TABLES,
        )
    conn.close()


if __name__ == "__main__":
    answer = input("Reset the database (deletes all data)? [y/N]: ").strip().lower()
    init_db(reset=(answer == "y"))
    print(f"Database ready at {DB_PATH}")
