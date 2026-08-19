#!/usr/bin/env python3
# social-recon/scripts/persian_lookup.py
import sys
import json
import requests
import time
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

def random_ua():
    return {"User-Agent": random.choice(USER_AGENTS)}

TARGET = sys.argv[1].replace("@", "")
OUTPUT = sys.argv[2]

platforms = {
    "telegram": f"https://t.me/{TARGET}",
    "aparat": f"https://www.aparat.com/{TARGET}",
    "filimo": f"https://www.filimo.com/portal/{TARGET}",
    "okala": f"https://okala.ir/search/?q={TARGET}",
    "hamijar": f"https://hamijar.ir/{TARGET}",
    "jobinja": f"https://jobinja.ir/search?keyword={TARGET}",
    "zoomg": f"https://zoomg.ir/?s={TARGET}",
    "snapp": f"https://snapp.ir/search?q={TARGET}",
    "divar": f"https://divar.ir/s/tehran?q={TARGET}",
    "digikala": f"https://www.digikala.com/search/?q={TARGET}",
    "bonyanat": f"https://bonyanat.ir/?s={TARGET}",
    "setareh": f"https://setareh.ir/?s={TARGET}",
    "technoava": f"https://technoava.com/?s={TARGET}",
    "khodemon": f"https://khodemon.com/search?q={TARGET}",
    "github": f"https://github.com/{TARGET}",
    "twitter": f"https://twitter.com/{TARGET}",
    "instagram": f"https://www.instagram.com/{TARGET}",
    "linkedin": f"https://www.linkedin.com/in/{TARGET}",
    "tiktok": f"https://www.tiktok.com/@{TARGET}",
    "youtube": f"https://www.youtube.com/@{TARGET}",
    "medium": f"https://medium.com/@{TARGET}",
    "stackoverflow": f"https://stackoverflow.com/users/{TARGET}",
    "reddit": f"https://www.reddit.com/user/{TARGET}",
    "pinterest": f"https://www.pinterest.com/{TARGET}",
    "twitch": f"https://www.twitch.tv/{TARGET}",
    "patreon": f"https://www.patreon.com/{TARGET}",
    "ko-fi": f"https://ko-fi.com/{TARGET}",
    "buy-me-a-coffee": f"https://www.buymeacoffee.com/{TARGET}",
    "mastodon": f"https://mastodon.social/@{TARGET}",
    "pixabay": f"https://pixabay.com/users/{TARGET}",
    "dev-to": f"https://dev.to/{TARGET}",
    "dribbble": f"https://dribbble.com/{TARGET}",
    "behance": f"https://www.behance.net/{TARGET}",
    "gitlab": f"https://gitlab.com/{TARGET}",
    "bitbucket": f"https://bitbucket.org/{TARGET}",
    "hackster": f"https://hackster.io/{TARGET}",
    "thingiverse": f"https://www.thingiverse.com/{TARGET}",
    "codepen": f"https://codepen.io/{TARGET}",
    "steam": f"https://steamcommunity.com/id/{TARGET}",
    "xbox": f"https://xboxgamertag.com/{TARGET}",
    "psn": f"https://psn.id/@{TARGET}",
}

results = {}

for name, url in platforms.items():
    try:
        r = requests.get(url, headers=random_ua(), timeout=10, allow_redirects=True)
        text = r.text.lower()
        exists = False
        signals = []

        if name == "github":
            exists = r.status_code == 200 and "not found" not in text
        elif name == "twitter":
            exists = r.status_code == 200 and "this account" not in text
        elif name == "instagram":
            exists = "instagram.com/" in r.url and "page not found" not in text
        elif name == "linkedin":
            exists = "linkedin.com/in/" in r.url and "not found" not in text
        elif name == "telegram":
            exists = r.status_code == 200 and "tgme_page_title" in text
        elif name == "tiktok":
            exists = f"tiktok.com/@{TARGET}" in r.url and r.status_code == 200
        elif name == "youtube":
            exists = "youtube.com/@" in r.url and r.status_code == 200 and "does not exist" not in text
        elif name == "medium":
            exists = "medium.com/@" in r.url and r.status_code == 200 and "page not found" not in text
        elif name == "stackoverflow":
            exists = "stackoverflow.com/users/" in r.url and r.status_code == 200 and "page not found" not in text
        elif name == "reddit":
            exists = "reddit.com/user/" in r.url and "user-not-found" not in r.url
        elif name == "twitch":
            exists = "twitch.tv/" in r.url and r.status_code == 200 and "not found" not in text
        elif name == "pinterest":
            exists = "pinterest.com/" in r.url and "page not found" not in text
        elif name == "dev-to":
            exists = "dev.to/" in r.url and r.status_code == 200
        elif name == "dribbble":
            exists = "dribbble.com/" in r.url and "doesn't exist" not in text
        elif name == "behance":
            exists = "behance.net/" in r.url and "not found" not in text
        elif name == "gitlab":
            exists = r.status_code == 200 and "gitlab.com/" in r.url and "does not exist" not in text
        elif name == "bitbucket":
            exists = r.status_code == 200 and "bitbucket.org/" in r.url and "not found" not in text
        elif name == "steam":
            exists = "steamcommunity.com/profiles/" in r.url or "steamcommunity.com/id/" in r.url
        elif name == "hackster":
            exists = "hackster.io/" in r.url and "not found" not in text
        elif name == "thingiverse":
            exists = "thingiverse.com/" in r.url and "not found" not in text
        elif name == "codepen":
            exists = "codepen.io/" in r.url and "not found" not in text
        elif r.status_code == 200:
            count = text.count(TARGET.lower())
            if count >= 3:
                exists = True
                signals.append(f"username appears {count} times")

        if exists:
            signals.append(f"HTTP {r.status_code}")
        
        results[name] = {
            "url": url,
            "exists": exists,
            "status_code": r.status_code,
            "final_url": r.url,
            "signals": signals
        }
    except Exception as e:
        results[name] = {
            "url": url,
            "exists": False,
            "error": str(e)
        }
    
    time.sleep(random.uniform(0.2, 0.8))

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] Recon saved to {OUTPUT}")