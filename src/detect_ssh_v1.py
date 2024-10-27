
#!/usr/bin/env python3
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (\S+) port \d+ ssh2"
)

def detect(lines):
    failures = defaultdict(list)

    for line in lines:
        try:
            event = json.loads(line)
            message = event.get("MESSAGE", "")
            match = PATTERN.search(message)

            if not match:
                continue

            timestamp = datetime.fromtimestamp(
                int(event["__REALTIME_TIMESTAMP"]) / 1_000_000,
                tz=timezone.utc
            )
            failures[match.group(1)].append(timestamp)

        except (ValueError, KeyError, TypeError):
            continue

    for ip, timestamps in failures.items():
        timestamps.sort()

        for i, timestamp in enumerate(timestamps):
            recent = [
                t for t in timestamps
                if timestamp - timedelta(minutes=5)
                <= t <= timestamp
            ]

            if len(recent) >= 5:
                alert = {
                    "rule": "SOC-001",
                    "severity": "medium",
                    "source_ip": ip,
                    "failed_attempts": len(recent),
                    "timestamp": timestamp.isoformat(),
                    "description": "Possible SSH brute-force"
                }
                print(json.dumps(alert))
                break

if __name__ == "__main__":
    detect(sys.stdin)
