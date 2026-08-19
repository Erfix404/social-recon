#!/usr/bin/env python3
"""search_dorks.py — advanced web dorks to find usernames, emails, phones from a name/keyword"""
import sys, json, os, re, time, random, requests

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

keywords = [
    f'"{TARGET}"',
    f'"{TARGET}" site:github.com OR site:linkedin.com OR site:twitter.com',
    f'"{TARGET}" "telegram" OR "t.me/"',
    f'"{Target}" site:instagram.com OR site:tiktok.com',
    f'"{Target}" site:reddit.com OR site:pinterest.com',
    f'"{Target}" site:stackoverflow.com OR site:medium.com',
]

results = {"target": TARGET, "search_hits": [], "emails_found": [], "usernames_found": [], "phones_found": []}
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"]

for q in keywords[:6]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": q},
                         headers={"User-Agent": random.choice(UA)}, timeout=10)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:6]):
                snip = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')
                results["search_hits"].append({"query": q[:60], "url": l, "snippet": snip[:200]})
                # Extract emails
                for em in re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', snip):
                    if em.lower() not in [x.lower() for x in results["emails_found"]]:
                        results["emails_found"].append(em)
                # Extract usernames
                for un in re.findall(r'@([\w]+)', snip):
                    if un != TARGET and un not in results["usernames_found"]:
                        results["usernames_found"].append(un)
                # Extract phone numbers
                for ph in re.findall(r'[\+]?[0-9][\d\s\-\(\)]{7,}', snip):
                    if ph not in results["phones_found"]:
                        results["phones_found"].append(ph)
        time.sleep(random.uniform(1.0, 2.5))
    except Exception as e:
        results["search_hits"].append({"error": str(e)})

with open(os.path.join(OUT_DIR, "search_dorks_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps(results))
