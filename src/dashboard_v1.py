
from flask import Flask, render_template_string
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

app = Flask(__name__)
DB = Path("/home/socadmin/pi-soc/database/soc.db")

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Pi-SOC Dashboard</title>
<style>
body {
  background:#0f172a; color:#e2e8f0;
  font-family:Arial,sans-serif; margin:30px;
}
h1 { color:#38bdf8; }
.cards { display:flex; gap:15px; flex-wrap:wrap; }
.card {
  background:#1e293b; padding:20px;
  border-radius:10px; min-width:130px;
}
.number { font-size:30px; font-weight:bold; }
table { width:100%; border-collapse:collapse; margin-top:20px; }
th,td { padding:12px; border-bottom:1px solid #334155; text-align:left; }
th { color:#38bdf8; }
.medium { color:#fbbf24; }
</style>
</head>
<body>
<h1>Pi-SOC Security Dashboard</h1>
<p>Raspberry Pi 3 | SQLite Detection Engine</p>

<div class="cards">
<div class="card">Total Alerts<div class="number">{{ total }}</div></div>
<div class="card">Open Alerts<div class="number">{{ open_count }}</div></div>
<div class="card">High Severity<div class="number">{{ high }}</div></div>
</div>

<h2>Recent Security Alerts</h2>
<table>
<tr>
<th>ID</th><th>Rule</th><th>Source IP</th>
<th>Severity</th><th>Failures</th><th>Status</th><th>UTC Time</th>
</tr>
{% for a in alerts %}
<tr>
<td>{{ a.id }}</td>
<td>{{ a.rule_id }}</td>
<td>{{ a.source_ip }}</td>
<td class="medium">{{ a.severity }}</td>
<td>{{ a.failure_count }}</td>
<td>{{ a.status }}</td>
<td>{{ a.timestamp }}</td>
</tr>
{% else %}
<tr><td colspan="7">No alerts detected yet</td></tr>
{% endfor %}
</table>
</body>
</html>
"""

@app.route("/")
def dashboard():
    with sqlite3.connect(f"file:{DB}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_count = db.execute(
            """SELECT COUNT(*) FROM alerts
       	       WHERE status IN ('new', 'investigating')"""
        ).fetchone()[0]
        high = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='high'"
        ).fetchone()[0]
        rows = db.execute(
            "SELECT * FROM alerts ORDER BY event_time DESC LIMIT 50"
        ).fetchall()

    alerts = []
    for row in rows:
        a = dict(row)
        a["timestamp"] = datetime.fromtimestamp(
            a["event_time"], timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        alerts.append(a)

    return render_template_string(
        HTML, total=total, open_count=open_count,
        high=high, alerts=alerts
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
