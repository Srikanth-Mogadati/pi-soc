
#!/usr/bin/env python3
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, abort, redirect, render_template_string,
    request, session, url_for
)

BASE = Path("/home/socadmin/pi-soc")
DB = BASE / "database" / "soc.db"
SECRET_FILE = Path(
    "/home/socadmin/.config/pi-soc/flask-secret"
)

app = Flask(__name__)
app.secret_key = SECRET_FILE.read_text().strip()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False
)

VALID_STATUSES = {
    "new", "investigating", "resolved", "false_positive"
}

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Pi-SOC Investigation Dashboard</title>
<style>
body {
  background:#0f172a; color:#e2e8f0;
  font-family:Arial,sans-serif;
  max-width:1100px; margin:30px auto; padding:0 16px;
}
h1,h2 {color:#38bdf8}
.cards {display:flex;flex-wrap:wrap;gap:15px}
.card {
  background:#1e293b;padding:20px;
  border-radius:10px;min-width:150px
}
.number {font-size:30px;font-weight:bold}
.panel {
  background:#1e293b;border-radius:10px;
  padding:20px;margin-top:20px
}
table {width:100%;border-collapse:collapse}
th,td {
  padding:12px;text-align:left;
  border-bottom:1px solid #334155
}
th {color:#38bdf8}
a {color:#38bdf8}
input,select,textarea {
  background:#0f172a;color:white;
  border:1px solid #475569;
  border-radius:5px;padding:10px;
  box-sizing:border-box;max-width:100%
}
textarea {width:100%;margin:12px 0}
button {
  background:#0284c7;color:white;
  padding:10px 18px;border:0;
  border-radius:6px;cursor:pointer
}
button:hover {background:#0369a1}
small {color:#94a3b8}
.table-wrap {overflow-x:auto}
</style>
</head>
<body>
<h1>Pi-SOC Security Dashboard</h1>
<p>Raspberry Pi 3 | SQLite Detection Engine</p>

<div class="cards">
<div class="card">Total Alerts
<div class="number">{{ total }}</div></div>
<div class="card">Open Alerts
<div class="number">{{ open_count }}</div></div>
<div class="card">High Severity
<div class="number">{{ high }}</div></div>
</div>

<h2>Recent Security Alerts</h2>
<div class="table-wrap">
<table>
<tr>
<th>ID</th><th>Rule</th><th>Source IP</th>
<th>Severity</th><th>Failures</th><th>Status</th>
<th>Action</th>
</tr>
{% for a in alerts %}
<tr>
<td>{{ a.id }}</td>
<td>{{ a.rule_id }}</td>
<td>{{ a.source_ip }}</td>
<td>{{ a.severity }}</td>
<td>{{ a.failure_count }}</td>
<td>{{ a.status }}</td>
<td><a href="{{ url_for('investigate', alert_id=a.id) }}">
Investigate</a></td>
</tr>
{% else %}
<tr><td colspan="7">No alerts detected yet</td></tr>
{% endfor %}
</table>
</div>

{% if selected %}
<div class="panel">
<h2>Investigate Alert #{{ selected.id }}</h2>
<p><strong>Rule:</strong> {{ selected.rule_id }}</p>
<p><strong>Source:</strong> {{ selected.source_ip }}</p>
<p><strong>Current status:</strong> {{ selected.status }}</p>

<form method="POST"
action="{{ url_for('update_alert', alert_id=selected.id) }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

<label for="status">Investigation status</label>
<select id="status" name="status" required>
{% for s in statuses %}
<option value="{{ s }}"
{% if selected.status == s %}selected{% endif %}>
{{ s.replace('_',' ').title() }}
</option>
{% endfor %}
</select>

<textarea name="note" rows="4" maxlength="2000"
placeholder="Describe investigation evidence and findings..."
required></textarea>

<button type="submit">Save Investigation</button>
</form>

<h2>Investigation History</h2>
{% for h in history %}
<div class="panel">
<strong>{{ h.old_status }} → {{ h.new_status }}</strong>
<p>{{ h.note }}</p>
<small>{{ h.analyst }} | {{ h.changed_at }} UTC</small>
</div>
{% else %}
<p>No investigation history recorded yet.</p>
{% endfor %}
</div>
{% endif %}
</body>
</html>
"""

def connect_db():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    return db

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.route("/")
@app.route("/alert/<int:alert_id>")
def investigate(alert_id=None):
    with connect_db() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        open_count = db.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE status IN ('new','investigating')"
        ).fetchone()[0]

        high = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='high'"
        ).fetchone()[0]

        alerts = db.execute(
            "SELECT * FROM alerts "
            "ORDER BY event_time DESC LIMIT 50"
        ).fetchall()

        selected = None
        history = []

        if alert_id is not None:
            selected = db.execute(
                "SELECT * FROM alerts WHERE id=?",
                (alert_id,)
            ).fetchone()

            if selected is None:
                abort(404)

            history = db.execute(
                "SELECT * FROM alert_history "
                "WHERE alert_id=? ORDER BY id DESC",
                (alert_id,)
            ).fetchall()

    return render_template_string(
        HTML,
        total=total,
        open_count=open_count,
        high=high,
        alerts=alerts,
        selected=selected,
        history=history,
        statuses=sorted(VALID_STATUSES),
        csrf_token=csrf_token()
    )

@app.post("/alert/<int:alert_id>/update")
def update_alert(alert_id):
    token = request.form.get("csrf_token", "")

    if not secrets.compare_digest(
        token, session.get("csrf_token", "")
    ) or not token:
        abort(403)

    new_status = request.form.get("status", "")
    note = request.form.get("note", "").strip()

    if new_status not in VALID_STATUSES:
        abort(400)

    if not note or len(note) > 2000:
        abort(400)

    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute(
            "SELECT status FROM alerts WHERE id=?",
            (alert_id,)
        ).fetchone()

        if row is None:
            abort(404)

        old_status = row["status"]

        db.execute(
            "UPDATE alerts SET status=? WHERE id=?",
            (new_status, alert_id)
        )

        db.execute(
            "INSERT INTO alert_history "
            "(alert_id,old_status,new_status,analyst,note) "
            "VALUES (?,?,?,?,?)",
            (
                alert_id, old_status, new_status,
                "socadmin", note
            )
        )

    return redirect(url_for("investigate", alert_id=alert_id))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

