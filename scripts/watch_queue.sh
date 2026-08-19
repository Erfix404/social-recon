#!/bin/bash
# social-recon/scripts/watch_queue.sh
# Checks queue.txt every 120s and runs chain.py on each target.
# Usage: nohup bash watch_queue.sh > ../watch.log 2>&1 &

QUEUE="/opt/data/skills/social-recon/queue.txt"
SCRIPTS="/opt/data/skills/social-recon/scripts"

while true; do
  if [ -s "$QUEUE" ]; then
    # Read first line
    TARGET=$(head -n 1 "$QUEUE")
    # Remove first line
    sed -i '1d' "$QUEUE"
    
    echo "[*] Processing target: $TARGET"
    python3 "$SCRIPTS/chain.py" "$TARGET" full 2>&1 | tee -a "../watch.log"
    echo "[*] Done processing $TARGET"
    echo "[*] Results in: output/$(echo "$TARGET" | tr '@ ' '__')/"
  else
    echo "[*] Queue empty. Waiting..."
  fi
  sleep 120
done