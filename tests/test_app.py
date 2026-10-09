"""Tests for the Flask dashboard, including its security controls."""

import re

import pytest

import db
import detect
from app import app
from conftest import write_log
from ingest import ingest


@pytest.fixture
def client(full_log):
    ingest(full_log)
    detect.main()
    app.config["TESTING"] = True
    return app.test_client()


def get_csrf_token(client, alert_id=1):
    page = client.get(f"/alert/{alert_id}").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def alert_status(alert_id):
    conn = db.get_connection()
    status = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
    conn.close()
    return status


def test_pages_load(client):
    assert client.get("/").status_code == 200
    assert client.get("/alert/1").status_code == 200
    assert client.get("/user/kbaptiste").status_code == 200


def test_missing_pages_return_404(client):
    assert client.get("/alert/9999").status_code == 404
    assert client.get("/user/nobody").status_code == 404


def test_severity_filter(client):
    page = client.get("/?severity=critical&status=all").get_data(as_text=True)
    assert page.count('class="badge sev-critical"') == 3
    assert 'class="badge sev-high"' not in page


def test_unknown_filter_values_are_ignored(client):
    page = client.get("/?severity=evil'--&status=hacked").get_data(as_text=True)
    assert page.count('class="badge sev-') == 6   # falls back to all open alerts


def test_status_change_without_csrf_token_is_refused(client):
    response = client.post("/alert/1/status", data={"status": "closed"})
    assert response.status_code == 400
    assert alert_status(1) == "open"


def test_status_change_with_wrong_csrf_token_is_refused(client):
    get_csrf_token(client)  # starts a session with a real token
    response = client.post("/alert/1/status",
                           data={"status": "closed", "csrf_token": "forged"})
    assert response.status_code == 400
    assert alert_status(1) == "open"


def test_status_change_with_valid_token_works(client):
    token = get_csrf_token(client)
    response = client.post("/alert/1/status",
                           data={"status": "investigating", "csrf_token": token})
    assert response.status_code == 302
    assert alert_status(1) == "investigating"


def test_unknown_status_is_refused(client):
    token = get_csrf_token(client)
    response = client.post("/alert/1/status",
                           data={"status": "deleted", "csrf_token": token})
    assert response.status_code == 400
    assert alert_status(1) == "open"


def test_log_content_cannot_inject_html(temp_db):
    """A username containing a <script> tag must be shown as text, not run."""
    attack = "<script>alert(1)</script>"
    events = [{"timestamp": "2026-10-06T10:00:00", "user": attack,
               "ip": "10.20.1.99", "action": "GRANT", "table": "payroll"}]
    ingest(write_log(temp_db / "xss.jsonl", events))
    detect.main()

    client = app.test_client()
    page = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
