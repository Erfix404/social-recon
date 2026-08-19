#!/usr/bin/env python3
# social-recon/scripts/deep_recon.py — v3 (lightweight initial collection)
# Extracts: emails (github commits, grep.app), phones (dorks), social profiles (from maigret.json),
#           telegram profile (t.me scrape), persian platforms, images.
# NO holehe, NO emailrep — those are in email_pipeline.py (chained separately).
import sys, json, re, time, random, os, requests

TARGET = sys.argv[1].replace("@", "").strip()
OUT_DIR = sys.argv[2]
IMG_DIR = os.path.join(OUT_DIR, "images")
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}
results = {
    "emails": [], "phones": [], "github_profile": {}, "github_events": [],
    "telegram_profile": {}, "search_hits": [], "persian_platforms": {},
    "images": [], "social_profiles": {}, "extracted_fullnames": []
}

def save():
    with open(os.path.join(OUT_DIR, "deep_recon.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def download_image(url, name):
    if not url:
        return
    try:
        r = requests.get(url, headers=UA, timeout=15)
        if r.status_code == 200 and len(r.content) > 500:
            ext = "jpg"
            ct = r.headers.get("content-type", "")
            if "png" in ct: ext = "png"
            elif "webp" in ct: ext = "webp"
            path = os.path.join(IMG_DIR, f"{name}.{ext}")
            with open(path, "wb") as f:
                f.write(r.content)
            import hashlib
            h = hashlib.md5(r.content).hexdigest()[:10]
            results["images"].append({"name": name, "path": path, "md5": h, "size": len(r.content)})
    except Exception:
        pass

# ---------- 1. Parse maigret.json ----------
print("[*] Parsing maigret.json...")
mg = load_json = {}
mg_path = os.path.join(OUT_DIR, "maigret.json")
if os.path.exists(mg_path):
    try:
        with open(mg_path, encoding="utf-8") as f:
            mg = json.load(f)
        for site, info in mg.items():
            if not isinstance(info, dict):
                continue
            st = info.get("status", {})
            if isinstance(st, dict) and st.get("status") == "Claimed":
                ids = st.get("ids", {})
                entry = {
                    "url": info.get("url_user", ""),
                    "fullname": ids.get("fullname") or ids.get("name"),
                    "id": ids.get("id"),
                    "bio": ids.get("bio"),
                    "image": ids.get("image") or ids.get("avatar"),
                    "private": ids.get("is_private"),
                    "follower_count": ids.get("follower_count"),
                    "verified": ids.get("is_verified"),
                    "location": ids.get("location") or ids.get("country"),
                }
                results["social_profiles"][site] = entry
                if entry["image"]:
                    download_image(entry["image"], site.lower())
                if entry.get("fullname") and len(entry["fullname"]) > 3:
                    results["extracted_fullnames"].append(entry["fullname"])
    except Exception:
        pass
save()

# ---------- 2. GitHub user + events ----------
print("[*] GitHub profile lookup...")
try:
    gh = requests.get(f"https://api.github.com/users/{TARGET}", headers={**UA, "Accept": "application/vnd.github+json"}, timeout=15).json()
    if gh.get("id"):
        results["github_profile"] = gh
        if gh.get("avatar_url"):
            download_image(gh["avatar_url"], "github_avatar")
        if gh.get("name"):
            results["extracted_fullnames"].append(gh["name"])
        ev = requests.get(f"https://api.github.com/users/{TARGET}/events/public",
                          headers={**UA, "Accept": "application/vnd.github+json"}, timeout=15).json()
        if isinstance(ev, list):
            results["github_events"] = [{"type": e.get("type"), "repo": e.get("repo", {}).get("name"), "created": e.get("created_at")} for e in ev[:50]]
except Exception as e:
    results["github_error"] = str(e)
save()

# ---------- 3. t.me scrape ----------
print("[*] t.me profile scrape...")
try:
    r = requests.get(f"https://t.me/{TARGET}", headers=UA, timeout=10)
    if r.status_code == 200 and "tgme_page_title" in r.text:
        title = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', r.text)
        desc = re.search(r'tgme_page_description[^>]*>\s*([^<]+)', r.text)
        photo = re.search(r'<img[^>]+src="([^"]+)"[^>]*class="tgme_page_photo_image"', r.text) or \
                re.search(r'<img[^>]+class="tgme_page_photo_image"[^>]+src="([^"]+)"', r.text)
        results["telegram_profile"] = {
            "username": TARGET,
            "title": title.group(1).strip() if title else None,
            "description": desc.group(1).strip() if desc else None,
            "photo_url": photo.group(1) if photo else None
        }
        if photo:
            download_image(photo.group(1), "telegram_profile")
except Exception:
    pass
save()

# ---------- 4. Email extraction (grep.app + github commits) ----------
print("[*] Extracting emails from code/repos...")
try:
    g = requests.get(f"https://grep.app/api/search?q={TARGET}", headers=UA, timeout=15)
    if g.status_code == 200:
        for h in g.json().get("hits", {}).get("hits", [])[:30]:
            snippet = h.get("content", {}).get("snippet", "")
            for em in re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', snippet):
                if em.lower() not in [x.lower() for x in results["emails"]]:
                    results["emails"].append(em)
            repo = h.get("repo", {}).get("raw", "")
            if repo:
                results["search_hits"].append({"repo": repo, "snippet": snippet[:200]})
except Exception:
    pass

try:
    ce = requests.get(f"https://api.github.com/search/commits?q=author:{TARGET}&sort=committer-date&order=desc",
                      headers={**UA, "Accept": "application/vnd.github+json"}, timeout=15)
    if ce.status_code == 200:
        for it in ce.json().get("items", [])[:25]:
            for key in ("author", "committer"):
                ca = it.get("commit", {}).get(key, {})
                if ca.get("email") and ca["email"].lower() not in [x.lower() for x in results["emails"]]:
                    results["emails"].append(ca["email"])
            repo_name = it.get("repo", {}).get("name", "")
            if repo_name:
                results["search_hits"].append({"repo": repo_name, "source": "github_commits"})
except Exception:
    pass
save()

# ---------- 5. Phone dorks ----------
print("[*] Running phone dorks...")
dork_queries = [f'"{TARGET}"']
if results["emails"]:
    primary = next((e for e in results["emails"] if "noreply" not in e and "github.com" not in e), results["emails"][0])
    dork_queries.append(f'"{primary}"')

# Add fullnames
for fn in results["extracted_fullnames"][:3]:
    dork_queries.append(f'"{fn}"')

phone_dorks = []
for q in dork_queries[:6]:
    phone_dorks += [
        f'{q} 09', f'{q} 0912', f'{q} 0935', f'{q} 0936', f'{q} 0919',
        f'{q} موبایل', f'{q} شماره تماس', f'{q} t.me',
        f'{q} site:divar.ir', f'{q} site:instagram.com', f'{q} site:sheypoor.com', f'{q} whatsapp',
        f'{q} "کد ملی"', f'{q} "شماره کارت"',
    ]

seen = set()
for d in phone_dorks:
    if d in seen:
        continue
    seen.add(d)
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": d}, headers=UA, timeout=8)
        if r.status_code == 200:
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            page_text = re.sub(r'<[^>]+>', ' ', ' '.join(snippets)).lower()
            for m in re.findall(r'(?:\+98|0)?\s?9\d{2}[\s\-]?\d{3}[\s\-]?\d{4}', page_text):
                clean = re.sub(r'[\s\-]', '', m)
                if not clean.startswith("99") and len(clean) >= 10:
                    if clean not in results["phones"]:
                        results["phones"].append(clean)
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            for i, l in enumerate(links[:5]):
                snip = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:150]
                entry = {"query": d[:70], "url": l, "snippet": snip}
                if entry not in results["search_hits"]:
                    results["search_hits"].append(entry)
    except Exception:
        pass
    time.sleep(random.uniform(0.5, 1.0))
save()

# ---------- 6. Persian platforms ----------
print("[*] Checking Persian platforms...")
persian_platforms = {
    "virgool": f"https://virgool.io/@{TARGET}",
    "quera": f"https://quera.org/profile/{TARGET}",
    "aparat": f"https://www.aparat.com/{TARGET}",
    "telegram": f"https://t.me/{TARGET}",
    "hamijar": f"https://hamijar.ir/{TARGET}",
    "jobinja": f"https://jobinja.ir/search?keyword={TARGET}",
    "zoomg": f"https://zoomg.ir/?s={TARGET}",
    "digikala": f"https://www.digikala.com/search/?q={TARGET}",
    "snapp": f"https://snapp.ir/search?q={TARGET}",
    "okala": f"https://okala.ir/search/?q={TARGET}",
    "filimo": f"https://www.filimo.com/search?q={TARGET}",
    "bonyanat": f"https://bonyanat.ir/?s={TARGET}",
    "setareh": f"https://setareh.ir/?s={TARGET}",
    "technoava": f"https://technoava.com/?s={TARGET}",
    "khodemon": f"https://khodemon.com/search?q={TARGET}",
}
for name, url in persian_platforms.items():
    try:
        r = requests.get(url, headers=UA, timeout=8, allow_redirects=True)
        text = r.text.lower()
        exists = r.status_code == 200 and ("not found" not in text and "خطا" not in text and "404" not in text)
        results["persian_platforms"][name] = {"url": url, "exists": exists, "status": r.status_code, "final_url": r.url}
    except Exception as e:
        results["persian_platforms"][name] = {"url": url, "exists": False, "error": str(e)}
    time.sleep(random.uniform(0.1, 0.3))
save()

# ---------- 7. Instagram reels/comments scrape ----------
print("[*] Checking Instagram reels/comments...")
try:
    r = requests.get(f"https://www.instagram.com/{TARGET}/", headers=UA, timeout=12)
    if r.status_code == 200 and "instagram.com/" in r.url:
        # Look for embedded profile data (not full scrape, just detect)
        bio_match = re.search(r'"description":"([^"]{0,300})"', r.text)
        if bio_match:
            results["instagram_bio"] = bio_match.group(1)
        # Look for reel links
        reels = re.findall(r'/reel/([A-Za-z0-9_\-]+)/', r.text)
        if reels:
            results["instagram_reels"] = reels[:10]
            results["instagram_profile_status"] = "public (reels visible)" if len(reels) > 0 else "public"
        else:
            results["instagram_profile_status"] = "private or no reels"
except Exception:
    pass
save()

print(f"[+] Deep recon v3 saved ({len(results['emails'])} emails, {len(results['phones'])} phones, {len(results['images'])} images, {len(results['social_profiles'])} profiles)")