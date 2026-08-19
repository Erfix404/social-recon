#!/usr/bin/env python3
"""
Phone Pipeline v2 — Persian-focused phone number OSINT.
Searches: PhoneInfoga, NumVerify, Tapsi/Snapp/Divar/Sheypoor dorks,
Instagram/Telegram profiles, card/national-code related searches.
"""
import sys, json, subprocess, requests, re, time, random, os

NUMBER = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {"phone": NUMBER, "phoneinfoga": {}, "numverify": {}, "search_hits": [], "ir_platforms": {}, "extracted_usernames": []}

# Normalize number for Persian formats
def normalize_persian(n):
    n = re.sub(r'[\s\-\(\)]', '', n)
    if n.startswith("+98"):
        n = "0" + n[3:]
    elif n.startswith("0098"):
        n = "0" + n[4:]
    return n

norm = normalize_persian(NUMBER)
results["normalized"] = norm

# --- PhoneInfoga ---
print("[*] Running PhoneInfoga...")
try:
    p = subprocess.run(["phoneinfoga", "scan", "phone", "--number", NUMBER],
                       capture_output=True, text=True, timeout=60)
    lines = p.stdout.strip().splitlines()
    found = []
    for l in lines:
        if any(k in l.lower() for k in ("carrier", "country", "line", "type", "status", "number", "valid", "format")):
            found.append(l.strip())
    results["phoneinfoga"] = {"output_tail": p.stdout[-2000:], "findings": found[:20]}
except Exception as e:
    results["phoneinfoga"] = {"error": str(e)}

# --- Numverify ---
print("[*] Running Numverify lookup...")
try:
    r = requests.get("https://apilayer.net/api/validate",
                     params={"number": norm, "country_code": "IR", "format": "json"}, timeout=12)
    if r.status_code == 200:
        results["numverify"] = r.json()
    else:
        results["numverify"] = {"status": r.status_code, "note": "Free tier needs API key for IR lookup"}
except Exception as e:
    results["numverify"] = {"error": str(e)}

# --- Persian platform dorks ---
platform_dorks = [
    f'"{norm}" site:divar.ir',
    f'"{norm}" site:sheypoor.com',
    f'"{norm}" site:snapp.ir OR site:tapsi.ir',
    f'"{norm}" site:instagram.com',
    f'"{norm}" site:t.me OR site:telegram.org',
    f'"{norm}" site:digikala.com OR site:okala.ir',
    f'"{norm}" site:jobinja.ir OR site:quera.org',
    f'"{norm}" "شماره" "تماس"',
    f'"{norm}" "دیوار" OR "شیپور" OR "اسنپ"',
    f'"{norm}" "کد ملی" OR "کدملی"',
    f'"{norm}" "شماره کارت" OR "کارت بانکی"',
    f'"{norm}" whatsapp OR واتساپ',
]

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
]

all_links = []
all_snippets = []

for q in platform_dorks[:10]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/",
                         params={"q": q}, headers={"User-Agent": random.choice(UA_LIST)}, timeout=12)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            all_links.extend(links[:5])
            page_text = re.sub(r'<[^>]+>', ' ', ' '.join(snippets)).lower()
            
            # Extract phone numbers found in snippets
            for m in re.findall(r'(?:\+98|0)?\s?9\d{2}[\s\-]?\d{3}[\s\-]?\d{4}', page_text):
                clean = re.sub(r'[\s\-]', '', m)
                if clean not in [h for h in results["search_hits"] if isinstance(h, str)]:
                    results["search_hits"].append(clean)
            
            # Extract card numbers (16 digits)
            for m in re.findall(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', page_text):
                clean = re.sub(r'[\s\-]', '', m)
                if clean not in results["search_hits"]:
                    results["search_hits"].append({"type": "card_number", "value": clean})
            
            # Extract national codes (10 digits starting with 0-9, not phone)
            for m in re.findall(r'\b\d{10}\b', page_text):
                if not m.startswith("9"):
                    results["search_hits"].append({"type": "national_code_candidate", "value": m})
            
            for i, l in enumerate(links[:5]):
                results["search_hits"].append({
                    "query": q[:50], "url": l,
                    "snippet": re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:180]
                })
        time.sleep(random.uniform(1.2, 2.5))
    except Exception as e:
        results["search_hits"].append({"error": str(e)})

# --- Direct platform checks (Tapsi, Snapp, Divar, Sheypoor) ---
ir_platforms = {
    "tapsi": f"https://tapsi.ir/search?phone={norm}",
    "snapp": f"https://app.snapp.taxi/search?phone={norm}",
    "divar": f"https://divar.ir/s/tehran?q={norm}",
    "sheypoor": f"https://www.sheypoor.com/s?query={norm}",
    "digikala": f"https://www.digikala.com/search/?q={norm}",
}

for name, url in ir_platforms.items():
    try:
        r = requests.get(url, headers={"User-Agent": random.choice(UA_LIST)}, timeout=12, allow_redirects=True)
        exists = r.status_code == 200 and "not found" not in r.text.lower()
        results["ir_platforms"][name] = {
            "url": url, "status": r.status_code, "exists": exists, "final_url": r.url
        }
    except Exception as e:
        results["ir_platforms"][name] = {"error": str(e)}
    time.sleep(random.uniform(0.5, 1.0))

# --- Extract usernames from snippets (for chain) ---
usernames = []
for h in results["search_hits"]:
    if isinstance(h, dict) and h.get("snippet"):
        m = re.findall(r'@([^\s@]+)', h["snippet"])
        usernames.extend(m)
    elif isinstance(h, str):
        pass
results["extracted_usernames"] = list(set(usernames))

with open(os.path.join(OUT_DIR, "phone_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] Phone pipeline v2 completed.")
print(f"[+] Normalized: {norm}")
print(f"[+] Search hits: {len([h for h in results['search_hits'] if isinstance(h, dict)])}")
print(f"[+] Iranian platforms checked: {len(results['ir_platforms'])}")
print(f"[+] Extracted usernames: {usernames[:5]}")
print(json.dumps(results))
