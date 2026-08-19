#!/bin/bash
# social-recon/run.sh — simple entry point
# Usage: ./run.sh TARGET [light|full|hawk]
# Example: ./run.sh @amirezamky9 full

TARGET="${1:-@amirezamky9}"
MODE="${2:-full}"

echo "[*] Omni-Recon: Starting on target: $TARGET (mode: $MODE)"
python3 scripts/chain.py "$TARGET" "$MODE"
echo "[*] Done."