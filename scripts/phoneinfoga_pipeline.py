#!/usr/bin/env python3
"""
PhoneInfoga Pipeline — Advanced phone number OSINT.
PhoneInfoga is a powerful, open-source, PII parser that can extract
information from a phone number using online sources.

https://github.com/ghostwalker1417/PhoneInfoga
"""
import sys, json, os, subprocess, re, time, random, requests

NUMBER = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {"phone": NUMBER, "phoneinfoga": {}, "search_hits": [], "errors": []}

# Normalize to E.164 format
def normalize(n):
    n = re.sub(r'[\s\-\(\)]', '', n)
    if n.startswith("+98"):
        n = "0" + n[3:]
    elif n.startswith("0098"):
        n = "0" + n[4:]
    return n

norm = normalize(NUMBER)
results["normalized"] = norm

# --- PhoneInfoga scan ---
print("[*] Running PhoneInfoga...")
try:
    # PhoneInfoga CLI (if installed)
    pi = subprocess.run(
        ["phoneinfoga", "phonetrack", "--phone", NUMBER, "--format", "json"],
        capture_output=True, text=True, timeout=60
    )
    if pi.returncode == 0:
        try:
            data = json.loads(pi.stdout)
            results["phoneinfoga"] = data
        except json.JSONDecodeError:
            results["phoneinfoga"] = {"raw_output": pi.stdout[:3000]}
    else:
        # Try pip-installed version
        pi = subprocess.run(
            ["python3", "-m", "phoneinfoga", "phonetrack", "--phone", NUMBER, "--format", "json"],
            capture_output=True, text=True, timeout=60
        )
        if pi.returncode == 0:
            try:
                data = json.loads(pi.stdout)
                results["phoneinfoga"] = data
            except json.JSONDecodeError:
                results["phoneinfoga"] = {"raw_output": pi.stdout[:3000]}
        else:
            results["phoneinfoga"] = {"error": "PhoneInfoga CLI not found or failed", "stderr": pi.stderr[:500]}
except Exception as e:
    results["phoneinfoga"] = {"error": str(e)}
    results["errors"].append(str(e))

# --- Web dorks for this number ---
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

dorks = [
    f'"{norm}" site:divar.ir OR site:sheypoor.com',
    f'"{norm}" site:snapp.ir OR site:tapsi.ir',
    f'"{norm}" site:instagram.com OR site:twitter.com',
    f'"{norm}" site:t.me OR site:telegram.org',
    f'"{norm}" site:digikala.com OR site:okala.ir',
    f'"{norm}" site:jobinja.ir OR site:quera.org',
    f'"{norm}" "کد ملی" OR "کدملی"',
    f'"{norm}" "شماره کارت" OR "کارت بانکی"',
    f'"{norm}" whatsapp OR واتساپ',
    f'"{norm}" bale.ir OR rubika.ir',
]

for q in dorks[:8]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/",
                         params={"q": q},
                         headers={"User-Agent": random.choice(UA_LIST)},
                         timeout=12)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:4]):
                snip = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                results["search_hits"].append({"query": q[:60], "url": l, "snippet": snip})
        time.sleep(random.uniform(1.0, 2.0))
    except Exception as e:
        pass

with open(os.path.join(OUT_DIR, "phoneinfoga_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({"phoneinfoga": bool(results.get("phoneinfoga")), "hits": len(results["search_hits"])}))