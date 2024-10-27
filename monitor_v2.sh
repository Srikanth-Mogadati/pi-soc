#!/bin/bash
set -euo pipefail

BASE=/home/socadmin/pi-soc
STATE="$BASE/state/ssh_state.json"

cd "$BASE"

if [ -f "$STATE" ]; then
    CURSOR=$(python3 -c \
      'import json,sys; print(json.load(open(sys.argv[1])).get("cursor") or "")' \
      "$STATE")
else
    CURSOR=""
fi

if [ -n "$CURSOR" ]; then
    journalctl -o json --after-cursor="$CURSOR" --no-pager \
      | python3 src/detect_ssh_v2.py \
      >> alerts/live-alerts-v2.jsonl
else
    journalctl -o json --since "5 minutes ago" --no-pager \
      | python3 src/detect_ssh_v2.py \
      >> alerts/live-alerts-v2.jsonl
fi
