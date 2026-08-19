#!/usr/bin/env python3
"""
Omni-Recon Chain v3 — orchestrates full OSINT pipeline.
Supports username, email, phone, domain, fullname.
Usage: python3 chain.py <target> [mode: light|full|hawk]

Chaining: username -> email/phone/name -> re-scan with found data
"""
import sys, json, os, subprocess, time, re

SCRIPTS = "/opt/data/skills/social-recon/scripts"
sys.path.insert(0, SCRIPTS)

TARGET = sys.argv[1]
MODE = sys.argv[2].lower() if len(sys.argv) > 2 else "full"
TARGET_CLEAN = TARGET.replace("@", "").replace(" ", "_")
OUT_DIR = f"/opt/data/skills/social-recon/output/{TARGET_CLEAN}"
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(os.path.join(OUT_DIR, "images"), exist_ok=True)

from input_classifier import classify
target_type, clean = classify(TARGET)

stages_run = []
print(f"[*] Target: {TARGET[:60]}")
print(f"[*] Classified: {target_type} -> {clean}")
print(f"[*] Mode: {MODE}")

def run(py_script, arg=None, name=None, timeout_sec=120):
    label = name or py_script.replace(".py", "")
    try:
        subprocess.run(
            ["python3", os.path.join(SCRIPTS, py_script), arg or clean, OUT_DIR],
            timeout=timeout_sec, stderr=subprocess.DEVNULL
        )
        stages_run.append(label)
    except Exception as e:
        print(f"[-] Error in {label}: {e}")

def run_maigret(username):
    """Run maigret, save report.json in output dir."""
    out_json = os.path.join(OUT_DIR, "maigret.json")
    if os.path.exists(out_json):
        stages_run.append("maigret")
        return
    try:
        subprocess.run(
            ["timeout", "120", "maigret", username, "--timeout", "8",
             "--no-progressbar", "--json", "simple"],
            cwd=SCRIPTS, timeout=150, stderr=subprocess.DEVNULL
        )
        # Maigret saves to reports/report_<username>_simple.json relative to cwd
        tmp = os.path.join(SCRIPTS, "reports", f"report_{username}_simple.json")
        if os.path.exists(tmp):
            os.replace(tmp, out_json)
        stages_run.append("maigret")
    except Exception as e:
        print(f"[-] Maigret error: {e}")

def load_json_file(name):
    p = os.path.join(OUT_DIR, name)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

# ==================== Stage 1: Initial Scan =================
print("\n=== Stage 1: Initial Scan ===")

if target_type == "username":
    run_maigret(clean)
    run("deep_recon.py", arg=TARGET, timeout_sec=300)
elif target_type == "email":
    run("email_pipeline.py", arg=clean, name="email_pipeline")
    # Also run maigret on username derived from email local-part
    username = clean.split("@")[0]
    run_maigret(username)
    run("deep_recon.py", arg=clean, timeout_sec=300)
elif target_type == "phone":
    run("phone_pipeline.py", arg=clean, name="phone_pipeline")
else:
    run("deep_recon.py", arg=TARGET, timeout_sec=300)

# ==================== Stage 2: Parse Results =================
print("\n=== Stage 2: Parse Results ===")

deep = load_json_file("deep_recon.json")
if not deep:
    deep = load_json_file("deep_recon")

# Merge social profiles from maigret.json if available
mg = load_json_file("maigret.json")
if not mg:
    mg = load_json_file("maigret_results.json")

if mg:
    profiles = {}
    for site, info in mg.items():
        if isinstance(info, dict):
            st = info.get("status", {})
            if isinstance(st, dict) and st.get("status") == "Claimed":
                ids = st.get("ids", {})
                profiles[site] = {
                    "url": info.get("url_user", info.get("url", "")),
                    "fullname": ids.get("fullname"),
                    "id": ids.get("id"),
                    "bio": ids.get("bio"),
                    "image": ids.get("image") or ids.get("avatar"),
                    "private": ids.get("is_private"),
                    "follower_count": ids.get("follower_count"),
                    "verified": ids.get("is_verified"),
                    "location": ids.get("location") or ids.get("country"),
                }
    deep["social_profiles"] = deep.get("social_profiles", {})
    deep["social_profiles"].update(profiles)

emails = list(dict.fromkeys(deep.get("emails", [])))
phones = list(dict.fromkeys(deep.get("phones", [])))

# Also collect emails/phones from maigret social_profiles
for site, info in deep.get("social_profiles", {}).items():
    fn = info.get("fullname") or ""
    if "@" in fn:
        for em in re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', fn):
            if em not in emails:
                emails.append(em)

# ==================== Stage 3: Chain Pipelines =================
print("\n=== Stage 3: Chained Pipelines ===")

if emails and "email_pipeline" not in stages_run:
    primary_email = next((e for e in emails if "noreply" not in e and "github.com" not in e), emails[0] if emails else "")
    if primary_email:
        print(f"[*] Chaining email pipeline on: {primary_email}")
        run("email_pipeline.py", arg=primary_email, name=f"email_pipeline({primary_email[:20]})")

if MODE == "full" and "deep_web_search" not in stages_run:
    print("[*] Running deep web + leak checks...")
    run("deep_web_search.py", arg=clean or TARGET, name="deep_web_search")
    for em in emails[:1]:
        if "noreply" not in em and "github.com" not in em:
            run("leak_checker.py", arg=em, name=f"leak_check({em[:15]})")

# ==================== Stage 4: Advanced Modules (Full/Hawk) =================
print("\n=== Stage 4: Advanced Modules ===")
if MODE in ("full", "hawk"):
    run("github_code_search.py", arg=clean, name="github_code_search")
    run("telegram_channel_search.py", arg=clean, name="telegram_channel_search")
    run("osint_ir_search.py", arg=clean, name="osint_ir_search")

# ==================== Stage 5: Final Report =================
print("\n=== Stage 5: Generating Final Report ===")

# Save stage log
with open(os.path.join(OUT_DIR, "stages_run.json"), "w", encoding="utf-8") as f:
    json.dump({
        "stages": stages_run,
        "input_type": target_type,
        "original_target": TARGET,
        "clean": clean,
        "mode": MODE,
        "emails_found": emails[:5],
        "phones_found": phones[:5]
    }, f, indent=2, ensure_ascii=False)

# Generate human-readable report
subprocess.run(["python3", os.path.join(SCRIPTS, "report.py"), OUT_DIR], timeout=30)
print(f"\n[✅] Omni-Recon v3 complete! {len(stages_run)} stages.")
print(f"[✅] Report: {OUT_DIR}/report.md")
print(f"[✅] JSON outputs: {OUT_DIR}/*.json")