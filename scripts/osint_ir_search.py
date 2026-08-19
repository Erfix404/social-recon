#!/usr/bin/env python3
"""
osint_ir_search.py — Use OSINT.ir tools and Persian resources for recon.
OSINT.ir provides categorized tools for different recon types.
"""
import sys, json, os, re, time, random, requests

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {"target": TARGET, "osint_ir_results": [], "persian_dorks": [], "iranian_resources_checked": []}

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}

# --- OSINT.ir resources for username search ---
osint_ir_keywords = [
    TARGET,
    f"@{TARGET}",
    f"https://t.me/{TARGET}",
    f"github.com/{TARGET}",
]

# --- Try direct API endpoints (if available) ---
# OSINT.ir doesn't expose public API but has categorized tools
osint_resources = {
    "google": f"https://www.google.com/search?q=%22{TARGET}%22",
    "bing": f"https://www.bing.com/search?q=%22{TARGET}%22",
    "yahoo": f"https://search.yahoo.com/search?p=%22{TARGET}%22",
    "yandex": f"https://yandex.com/search/?text=%22{TARGET}%22",
    "baidu": f"https://www.baidu.com/s?wd=%22{TARGET}%22",
    "duckduckgo": f"https://html.duckduckgo.com/html/?q=%22{TARGET}%22",
    "github_code": f"https://github.com/search?q=%22{Target}%22&type=code",
    "github_repos": f"https://github.com/{TARGET}?tab=repositories",
    "instagram": f"https://www.instagram.com/{TARGET}/",
    "twitter": f"https://twitter.com/{TARGET}",
    "telegram": f"https://t.me/{TARGET}",
    "linkedin": f"https://www.linkedin.com/in/{TARGET}/",
    "medium": f"https://medium.com/@{TARGET}",
    "reddit": f"https://www.reddit.com/user/{TARGET}",
    "youtube": f"https://www.youtube.com/@{Target}",
    "pinterest": f"https://www.pinterest.com/{TARGET}/",
    "tiktok": f"https://www.tiktok.com/@{Target}",
    "facebook": f"https://www.facebook.com/{TARGET}",
    "snapchat": f"https://www.snapchat.com/add/{TARGET}",
    "discord": f"https://discordapp.com/users/{TARGET}",
    "steam": f"https://steamcommunity.com/id/{TARGET}",
    "twitch": f"https://www.twitch.tv/{TARGET}",
    "patreon": f"https://www.patreon.com/{TARGET}",
    "dev_to": f"https://dev.to/{TARGET}",
    "dribbble": f"https://dribbble.com/{Target}",
    "behance": f"https://www.behance.net/{Target}",
    "gitlab": f"https://gitlab.com/{TARGET}",
    "bitbucket": f"https://bitbucket.org/{Target}",
}

# Check key resources
key_resources = ["google", "yandex", "baidu", "github_code", "github_repos", "linkedin", "medium", "reddit", "youtube"]

for res_name in key_resources:
    url = osint_resources.get(res_name, "")
    if not url:
        continue
    try:
        r = requests.get(url, headers=UA, timeout=12)
        text_len = len(r.text)
        title_match = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else "No title"
        
        entry = {
            "resource": res_name,
            "url": url,
            "status_code": r.status_code,
            "final_url": r.url,
            "content_length": text_len,
            "title": title[:100],
            "target_found": TARGET.lower() in r.text.lower() and "not found" not in r.text.lower() and r.status_code in [200, 201, 202, 203, 204]
        }
        results["osint_ir_results"].append(entry)
        results["iranian_resources_checked"].append(res_name)
    except Exception as e:
        results["osint_ir_results"].append({"resource": res_name, "url": url, "error": str(e)})
    time.sleep(random.uniform(0.8, 1.5))

# --- Persian-specific dorks ---
persian_queries = [
    f'"{TARGET}" "ایران" OR "تهران" OR "ایرانی"',
    f'"{TARGET}" "کد ملی" OR "شماره ملی"',
    f'"{TARGET}" "کارت بانکی" OR "شماره کارت"',
    f'"{TARGET}" "تلگرام" OR "واتساپ" OR "تماس"',
    f'"{TARGET}" "استخدام" OR "شغل" OR "رزومه"',
    f'"{TARGET}" "دانشجو" OR "دانشگاه" OR "دانشکده"',
    f'"{TARGET}" "فروش" OR "خرید" OR "دیوار"',
    f'site:divar.ir "{TARGET}"',
    f'site:hamijar.ir "{TARGET}"',
    f'site:jobinja.ir "{TARGET}"',
]

for q in persian_queries[:6]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": q},
                         headers=UA, timeout=10)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:3]):
                if not any(x.get("url") == l for x in results["persian_dorks"]):
                    results["persian_dorks"].append({
                        "query": q[:50], "url": l,
                        "snippet": re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                    })
        time.sleep(random.uniform(1.5, 2.5))
    except Exception:
        pass

# Save
with open(os.path.join(OUT_DIR, "osint_ir_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] OSINT.ir scan done. Resources checked: {len(results['iranian_resources_checked'])}")
print(f"[+] Persian dorks hits: {len(results['persian_dorks'])}")
print(json.dumps(results))