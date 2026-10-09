"""AuditSentinel web dashboard.

Run:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import os
import secrets

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for

from db import get_connection

app = Flask(__name__)

# The secret key signs the session cookie. Set AUDITSENTINEL_SECRET in real
# deployments; otherwise a random key is made on each start.
app.secret_key = os.environ.get("AUDITSENTINEL_SECRET") or secrets.token_hex(32)

SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["open", "investigating", "closed"]
SEVERITY_ORDER = (
    "CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 ELSE 3 END"
)


# ---------------------------------------------------------------------------
# CSRF protection: every form that changes data carries a secret token that
# only our own pages know. A malicious site can't forge the request without it.
# ---------------------------------------------------------------------------
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session.get("csrf_token", "")):
            abort(400, "Invalid or missing CSRF token")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    # Only accept filter values we know about (whitelisting)
    severity = request.args.get("severity", "")
    status = request.args.get("status", "open")
    rule = request.args.get("rule", "")
    if severity not in SEVERITIES:
        severity = ""
    if status not in STATUSES + ["all"]:
        status = "open"

    conn = get_connection()
    rules = [r["rule_name"] for r in conn.execute(
        "SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name")]
    if rule not in rules:
        rule = ""

    # Build the WHERE clause from fixed pieces; user values only go in params
    conditions, params = [], []
    if severity:
        conditions.append("a.severity = ?")
        params.append(severity)
    if status != "all":
        conditions.append("a.status = ?")
        params.append(status)
    if rule:
        conditions.append("a.rule_name = ?")
        params.append(rule)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    alerts = conn.execute(
        f"""
        SELECT a.*, COUNT(ae.event_id) AS evidence
        FROM alerts a
        LEFT JOIN alert_events ae ON ae.alert_id = a.id
        {where}
        GROUP BY a.id
        ORDER BY {SEVERITY_ORDER}, a.id
        """,
        params,
    ).fetchall()

    counts = {s: 0 for s in SEVERITIES}
    for r in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE status <> 'closed' GROUP BY severity"
    ):
        counts[r["severity"]] = r["n"]

    totals = conn.execute(
        """
        SELECT (SELECT COUNT(*) FROM audit_events) AS events,
               (SELECT COUNT(*) FROM alerts WHERE status = 'open') AS open_alerts,
               (SELECT COUNT(*) FROM alerts WHERE status = 'investigating') AS investigating
        """
    ).fetchone()
    conn.close()

    return render_template(
        "index.html", alerts=alerts, counts=counts, totals=totals,
        rules=rules, severities=SEVERITIES, statuses=STATUSES,
        f_severity=severity, f_status=status, f_rule=rule,
    )


@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id):
    conn = get_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        abort(404)

    events = conn.execute(
        """
        SELECT e.*, s.sensitivity
        FROM alert_events ae
        JOIN audit_events e ON e.id = ae.event_id
        LEFT JOIN sensitive_tables s ON s.table_name = e.target_table
        WHERE ae.alert_id = ?
        ORDER BY e.event_time
        """,
        (alert_id,),
    ).fetchall()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (alert["username"],)
    ).fetchone()

    related = conn.execute(
        """
        SELECT id, rule_name, severity, status FROM alerts
        WHERE username = ? AND id <> ?
        ORDER BY id
        """,
        (alert["username"], alert_id),
    ).fetchall()
    conn.close()

    return render_template(
        "alert.html", alert=alert, events=events, user=user,
        related=related, statuses=STATUSES,
    )


@app.route("/alert/<int:alert_id>/status", methods=["POST"])
def update_status(alert_id):
    new_status = request.form.get("status", "")
    if new_status not in STATUSES:
        abort(400, "Unknown status")

    conn = get_connection()
    with conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id)
        )
    conn.close()
    if cursor.rowcount == 0:
        abort(404)

    flash(f"Alert #{alert_id} marked as {new_status}.")
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/user/<username>")
def user_activity(username):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    events = conn.execute(
        """
        SELECT e.*, s.sensitivity,
               EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = e.id) AS flagged
        FROM audit_events e
        LEFT JOIN sensitive_tables s ON s.table_name = e.target_table
        WHERE e.username = ?
        ORDER BY e.event_time
        """,
        (username,),
    ).fetchall()
    if user is None and not events:
        conn.close()
        abort(404)

    ips = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS n FROM audit_events
        WHERE username = ? GROUP BY source_ip ORDER BY n DESC
        """,
        (username,),
    ).fetchall()
    conn.close()

    return render_template(
        "user.html", username=username, user=user, events=events, ips=ips,
        flagged_count=sum(1 for e in events if e["flagged"]),
    )


@app.errorhandler(404)
def not_found(_err):
    return render_template("error.html", message="Not found."), 404


@app.errorhandler(400)
def bad_request(err):
    return render_template("error.html", message=err.description), 400


if __name__ == "__main__":
    # 127.0.0.1 = only this computer can reach the dashboard.
    # Debug mode stays off: it can expose a code console to anyone who reaches it.
    app.run(host="127.0.0.1", port=5000, debug=False)
