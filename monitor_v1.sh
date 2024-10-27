#!/bin/bash
set -euo pipefail

cd /home/socadmin/pi-soc

journalctl -o json --since "5 minutes ago" --no-pager \
  | python3 src/detect_ssh.py \
  >> alerts/live-alerts.jsonl
