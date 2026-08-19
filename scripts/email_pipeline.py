#!/usr/bin/env python3
"""Email Pipeline — Holehe + Hunter + EmailRep + HaveIBeenPwned"""
import sys, json, subprocess, requests, time

EMAIL = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)
results = {"email": EMAIL, "holehe": {}, "emailrep": {}, "hibp": {}, "hunter": {}}

# --- Holehe ---
print("[*] Running holehe...")
try:
    p = subprocess.run(["holehe", EMAIL, "--no-color", "--only-used"],
                       capture_output=True, text=True, timeout=120)
    out = p.stdout
    found = []
    for line in out.splitlines():
        if "[+]" in line or "[" in line and "Found" in line:
            found.append(line.strip())
    results["holehe"] = {"output_tail": out[-1500:], "found_count": len(found), "found_lines": found[-20:]}
except Exception as e:
    results["holehe"] = {"error": str(e)}

# --- EmailRep ---
print("[*] Running EmailRep...")
try:
    r = requests.get(f"https://emailrep.io/{EMAIL}", headers={"User-Agent": "emailrep-python/0.0.1"}, timeout=15)
    if r.status_code == 200:
        data = r.json()
        results["emailrep"] = {
            "reputation": data.get("reputation"),
            "suspicious": data.get("suspicious"),
            "references": data.get("references"),
            "details": data.get("details", {})
        }
    else:
        results["emailrep"] = {"status": r.status_code, "error": "rate limited or blocked"}
except Exception as e:
    results["emailrep"] = {"error": str(e)}

# --- HaveIBeenPwned (no auth, limited) ---
print("[*] Running HIBP check...")
try:
    # HIBP requires API key for breach search; we'll just note it
    results["hibp"] = {
        "note": "HIBP requires API key. Use https://haveibeenpwned.com/API/v3 for full breach data.",
        "manual_check_url": f"https://haveibeenpwned.com/account/{EMAIL}"
    }
except Exception as e:
    results["hibp"] = {"error": str(e)}

# --- Hunter.io (domain extraction) ---
if "@" in EMAIL:
    domain = EMAIL.split("@")[1]
    print(f"[*] Running Hunter.io on domain: {domain}")
    try:
        r = requests.get("https://api.hunter.io/v2/domain-search",
                         params={"domain": domain, "api_key": ""}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            results["hunter"] = {
                "total": data.get("total"),
                "emails": [{"email": e.get("value"), "type": e.get("type"), "first_name": e.get("first_name")}
                           for e in data.get("emails", [])[:10]]
            }
        else:
            results["hunter"] = {"status": r.status_code, "note": "Hunter.io API key required"}
    except Exception as e:
        results["hunter"] = {"error": str(e)}

# Save results
with open(os.path.join(OUT_DIR, "email_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# Return any phone numbers found (for chain)
phones = []
for line in results.get("holehe", {}).get("found_lines", []):
    m = re.findall(r'[\+]?[\d]{7,15}', line)
    phones.extend(m)
results["extracted_phones"] = phones

print(f"[+] Email pipeline completed. Emails with data: {len(results.get('holehe', {}).get('found_lines', []))}")
print(f"[+] Extracted phones: {phones}")
print(json.dumps(results))
