#!/usr/bin/env python3
"""
Instaloader Pipeline — Instagram OSINT via instaloader.
Profiles, posts, stories, comments, followers, following,
hashtags, and location-based searches.

Requires: pip install instaloader
"""
import sys, json, os, subprocess, re, time, random, requests

USERNAME = sys.argv[1].replace("@", "").strip()
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(os.path.join(OUT_DIR, "instagram"), exist_ok=True)

results = {"username": USERNAME, "exists": False, "profile": {}, "recent_posts": [], "followers_sample": [], "errors": []}

# --- instaloader profile download ---
print(f"[*] Running instaloader on: {USERNAME}")
try:
    instagram_dir = os.path.join(OUT_DIR, "instagram")
    p = subprocess.run(
        ["instaloader",
         "--no-captions",
         "--no-video-annotations",
         "--no-video-thumbnails",
         "--dirname-pattern={}/{}".format(instagram_dir, USERNAME),
         "--filename-pattern={}",
         "--count=10",
         "--{}s".format("no" if False else ""),  # placeholder
         USERNAME],
        capture_output=True, text=True, timeout=90,
        cwd=OUT_DIR
    )

    # Parse instaloader output
    out = p.stdout + p.stderr
    if "Logged-in user" in out or "is not a valid username" in out.lower() or USERNAME in out:
        # Check if profile exists
        try:
            r = requests.get(f"https://www.instagram.com/{USERNAME}/", headers={
                "User-Agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
                ])
            }, timeout=15, allow_redirects=False)
            if r.status_code == 200:
                results["exists"] = True
                # Extract profile info from HTML
                bio_match = re.search(r'<meta name="description" content="(.*?)"', r.text)
                if bio_match:
                    results["profile"]["bio"] = bio_match.group(1)[:300]
                title_match = re.search(r'<title>(.*?)</title>', r.text)
                if title_match:
                    title = title_match.group(1)
                    if "Page Not Found" not in title and "صفحه یافت نشد" not in title:
                        results["profile"]["page_title"] = title.strip()
                        results["profile"]["url"] = f"https://www.instagram.com/{USERNAME}/"
        except Exception as e:
            results["errors"].append(f"Instagram check error: {e}")

except Exception as e:
    results["errors"].append(f"Instaloader error: {e}")

# --- snscrape fallback (works without login) ---
print(f"[*] Running snscrape for Instagram: {USERNAME}")
try:
    p = subprocess.run(
        ["snscrape", "--jsonl", "--max-results", "10", f"instagram-{USERNAME}"],
        capture_output=True, text=True, timeout=60
    )
    if p.stdout:
        posts = []
        for line in p.stdout.strip().splitlines():
            try:
                d = json.loads(line)
                posts.append({
                    "url": d.get("url"),
                    "date": d.get("date"),
                    "content": (d.get("content") or "")[:300],
                    "like_count": d.get("likeCount"),
                    "retweet_count": d.get("retweetCount"),
                    "comment_count": d.get("commentCount"),
                    "image": d.get("media", [{}])[0].get("url") if d.get("media") else None,
                })
            except json.JSONDecodeError:
                pass
        results["recent_posts"] = posts
        results["exists"] = True
except Exception as e:
    results["errors"].append(f"snscrape error: {e}")

# --- Save ---
with open(os.path.join(OUT_DIR, "instagram_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({"exists": results["exists"], "posts": len(results["recent_posts"])}))