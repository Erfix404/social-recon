#!/bin/bash
# social-recon/run.sh
# Eagle-eye OSINT recon — v2

TARGET=$1
OUT_DIR="/opt/data/skills/social-recon/output/${TARGET}"
mkdir -p "$OUT_DIR"

echo "[*] Starting eagle-eye recon on: $TARGET"
echo "[*] Output directory: $OUT_DIR"
rm -rf "$OUT_DIR"/*

# --- Maigret (3000+ sites) ---
echo "[*] Running Maigret..."
timeout 150 maigret "$TARGET" --timeout 10 --no-progressbar --json simple 2>/dev/null
if [ -f "reports/report_${TARGET}_simple.json" ]; then
    cp "reports/report_${TARGET}_simple.json" "$OUT_DIR/maigret.json"
    echo "[+] Maigret finished (report copied)."
else
    echo "[-] Maigret no report."
fi

# --- Sherlock backup ---
echo "[*] Running Sherlock..."
timeout 90 python3 -m sherlock "$TARGET" --json "$OUT_DIR/sherlock.json" --timeout 10 2>/dev/null || true
echo "[+] Sherlock done."

# --- theHarvester for domains ---
if [[ $TARGET =~ [a-z0-9-]+\.(com|ir|net|org|io|dev|me|info|xyz) ]]; then
    echo "[*] Running theHarvester..."
    theHarvester -d "$TARGET" -l 200 -b all -f "$OUT_DIR/harvester.html" 2>/dev/null || true
fi

# --- Telegram lookup ---
echo "[*] Running Telegram lookup..."
curl -s "https://api.telegram.org/bot8815645031:AAEr2tcvHZFdTXGW8YfjoCsecYe1ksJkNeg/getChat?chat_id=@${TARGET}" -o "$OUT_DIR/telegram.json" 2>/dev/null
echo "[+] Telegram lookup done."

# --- Deep recon v2 (multi-stage with save() between stages) ---
echo "[*] Running deep recon..."
python3 /opt/data/skills/social-recon/scripts/deep_recon.py "$TARGET" "$OUT_DIR" 2>&1 | tail -3
echo "[+] Deep recon done."

# --- Generate report ---
echo "[*] Generating final report..."
python3 /opt/data/skills/social-recon/scripts/report.py "$OUT_DIR" > "$OUT_DIR/report.md"
echo "[✅] Total images: $(ls "$OUT_DIR/images" 2>/dev/null | wc -l)"
echo "[✅] Report saved at: $OUT_DIR/report.md"
ls -la "$OUT_DIR"