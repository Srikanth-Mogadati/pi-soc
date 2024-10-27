
#!/usr/bin/env python3
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE = Path("/home/socadmin/pi-soc")
STATE_FILE = BASE / "state" / "ssh_state.json"

WINDOW_SECONDS = 300
THRESHOLD = 5

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (\S+) port \d+ ssh2"
)

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"cursor": None, "failures": {}, "last_alert": {}}

def save_state(state):
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2))
    temporary.replace(STATE_FILE)

def process(events, state):
    failures = defaultdict(
        list, state.get("failures", {})
    )
    last_alert = state.get("last_alert", {})
    alerts = []

    for event in events:
        cursor = event.get("__CURSOR")
        if cursor:
            state["cursor"] = cursor

        try:
            ts = int(event["__REALTIME_TIMESTAMP"]) / 1_000_000
            message = event.get("MESSAGE", "")
        except (ValueError, KeyError, TypeError):
            continue

        # Remove expired failures
        for ip in list(failures):
            failures[ip] = [
                t for t in failures[ip]
                if ts - t <= WINDOW_SECONDS
            ]
            if not failures[ip]:
                del failures[ip]

        match = PATTERN.search(message)
        if not match:
            continue

        ip = match.group(1)
        failures[ip].append(ts)

        if len(failures[ip]) >= THRESHOLD:
            previous = last_alert.get(ip, 0)

            if ts - previous >= WINDOW_SECONDS:
                alerts.append({
                    "rule": "SOC-001",
                    "severity": "medium",
                    "source_ip": ip,
                    "failed_attempts": len(failures[ip]),
                    "timestamp": datetime.fromtimestamp(
                        ts, timezone.utc
                    ).isoformat(),
                    "description": "Possible SSH brute-force"
                })
                last_alert[ip] = ts

    state["failures"] = dict(failures)
    state["last_alert"] = last_alert
    return alerts

def main():
    state = load_state()
    events = [json.loads(line) for line in sys.stdin if line.strip()]
    alerts = process(events, state)

    for alert in alerts:
        print(json.dumps(alert))

    save_state(state)

if __name__ == "__main__":
    main()
