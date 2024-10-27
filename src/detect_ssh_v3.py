
#!/usr/bin/env python3
import argparse
import json
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/home/socadmin/pi-soc")
DEFAULT_DB = BASE / "database" / "soc.db"
WINDOW = 300
THRESHOLD = 5

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (\S+) port \d+ ssh2"
)

def get_events(db, input_file=None):
    cursor_row = db.execute(
        "SELECT value FROM metadata WHERE key='cursor'"
    ).fetchone()
    cursor = cursor_row[0] if cursor_row else None

    if input_file:
        with open(input_file, encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]

        # Replay-safe for ordered test fixtures with unique cursors.
        if cursor:
            positions = [
                i for i, e in enumerate(events)
                if e.get("__CURSOR") == cursor
            ]
            if positions:
                events = events[positions[-1] + 1:]
            else:
                raise ValueError("Saved cursor missing from test fixture")
        return events

    cmd = ["journalctl", "-o", "json", "--no-pager"]

    if cursor:
        cmd.append("--after-cursor=" + cursor)
    else:
        cmd.extend(["--since", "5 minutes ago"])

    result = subprocess.run(
        cmd, capture_output=True, text=True, check=True
    )
    return [
        json.loads(line)
        for line in result.stdout.splitlines()
        if line.strip()
    ]

def process(db, events):
    alerts_created = 0

    with db:
        for event in events:
            cursor = event.get("__CURSOR")
            if not cursor:
                raise ValueError("Event has no journal cursor")

            # Cursor and detection changes share a transaction.
            db.execute(
                "INSERT OR REPLACE INTO metadata(key,value) "
                "VALUES('cursor',?)",
                (cursor,)
            )

            try:
                ts = int(event["__REALTIME_TIMESTAMP"]) / 1_000_000
                message = event.get("MESSAGE", "")
            except (KeyError, ValueError, TypeError):
                continue

            match = PATTERN.search(message)
            if not match:
                continue

            ip = match.group(1)

            db.execute(
                "DELETE FROM ssh_failures WHERE event_time < ?",
                (ts - WINDOW,)
            )

            db.execute(
                "INSERT INTO ssh_failures(source_ip,event_time) "
                "VALUES(?,?)",
                (ip, ts)
            )

            count = db.execute(
                "SELECT COUNT(*) FROM ssh_failures "
                "WHERE source_ip=? AND event_time BETWEEN ? AND ?",
                (ip, ts - WINDOW, ts)
            ).fetchone()[0]

            previous = db.execute(
                "SELECT MAX(event_time) FROM alerts "
                "WHERE rule_id='SOC-001' AND source_ip=?",
                (ip,)
            ).fetchone()[0]

            if count >= THRESHOLD and (
                previous is None or ts - previous >= WINDOW
            ):
                db.execute(
                    "INSERT INTO alerts "
                    "(rule_id,source_ip,severity,event_time,"
                    "failure_count,status) "
                    "VALUES (?,?,?,?,?,'new')",
                    ("SOC-001", ip, "medium", ts, count)
                )
                alerts_created += 1

    return alerts_created

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--input-file")
    args = parser.parse_args()

    with sqlite3.connect(args.db, timeout=30) as db:
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("BEGIN IMMEDIATE")
        try:
            events = get_events(db, args.input_file)
            count = process(db, events)
        except Exception:
            db.rollback()
            raise

    print(f"Processed {len(events)} events; new alerts: {count}")

if __name__ == "__main__":
    main()
