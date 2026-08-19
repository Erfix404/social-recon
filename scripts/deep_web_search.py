#!/usr/bin/env python3
"""
deep_web_search.py — Search Wayback Machine CDX API and Common Crawl
for historical mentions of the target.
"""
import sys, json, os, re, time, requests
from datetime import datetime

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {"target": TARGET, "wayback_urls": [], "wayback_content": [], "commoncrawl_hits": [], "search_hits": []}

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}

# --- Wayback Machine CDX API ---
print(f"[*] Searching Wayback Machine for: {TARGET}...")
try:
    r = requests.get("https://web.archive.org/cdx/search/cdx",
                     params={"url": f"*{TARGET}*", "output": "json", "limit": 50, "filter": "statuscode:200"},
                     headers=UA, timeout=30)
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, list) and len(data) > 1:
            headers = data[0]
            for row in data[1:]:
                results["wayback_urls"].append(dict(zip(headers, row)))
            print(f"[+] Wayback: Found {len(results['wayback_urls'])} snapshots")
        else:
            print("[*] Wayback: No results")
except Exception as e:
    results["wayback_error"] = str(e)
    print(f"[-] Wayback error: {e}")

# --- Common Crawl Index ---
print("[*] Searching Common Crawl...")
try:
    cc = requests.get("http://index.commoncrawl.org/CC-MAIN-2024-38-index",
                      params={"url": f"*.{TARGET}*", "output": "json", "limit": 50},
                      headers=UA, timeout=30)
    if cc.status_code == 200:
        for line in cc.text.strip().splitlines():
            try:
                obj = json.loads(line)
                results["commoncrawl_hits"].append(obj)
            except Exception:
                pass
        print(f"[+] CommonCrawl: Found {len(results['commoncrawl_hits'])} hits")
except Exception as e:
    results["commoncrawl_error"] = str(e)

# --- Web search dorks ---
print("[*] Running web dorks...")
queries = [
    f'"{TARGET}" site:web.archive.org',
    f'intext:"{TARGET}" filetype:json OR filetype:xml',
    f'"{TARGET}" "email" OR "contact" OR "phone"',
    f'"{TARGET}" " Iranian" OR "ایران" -site:t.me',
]
for q in queries[:4]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": q},
                         headers={"User-Agent": UA["User-Agent"]}, timeout=10)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:5]):
                results["search_hits"].append({
                    "query": q[:50], "url": l,
                    "snippet": re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                })
        time.sleep(1.5)
    except Exception:
        pass

# --- Search for target in Persian web archives ---
persian_dorks = [
    f'"{TARGET}" site:web.archive.org "iran" OR "تهران"',
    f'"{TARGET}" intitle:"درباره" OR intitle:"پروفایل"',
    f'"{TARGET}" inurl:profile OR inurl:contact',
]
for pd in persian_dorks[:2]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": pd}, headers=UA, timeout=10)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:5]):
                if l not in [x.get("url") for x in results["search_hits"]]:
                    results["search_hits"].append({
                        "query": pd[:50], "url": l,
                        "snippet": re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                    })
        time.sleep(2)
    except Exception:
        pass

with open(os.path.join(OUT_DIR, "deep_web_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] Deep web search done. Wayback: {len(results['wayback_urls'])}, CC: {len(results['commoncrawl_hits'])}, Search: {len(results['search_hits'])}")
print(json.dumps(results))