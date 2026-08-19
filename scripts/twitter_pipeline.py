#!/usr/bin/env python3
"""
Twitter/X Recon Pipeline — via snscrape (no API key needed).
Search username, scrape profile, recent tweets, mentions, and
search for the target across the platform.
"""
import sys, json, os, subprocess, re, time, requests, random

USERNAME = sys.argv[1].replace("@", "").strip()
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {
    "username": USERNAME,
    "exists": False,
    "profile": {},
    "recent_tweets": [],
    "mentions": [],
    "search_results": [],
    "errors": []
}

# --- Check if profile exists (via t.me and direct) ---
print(f"[*] Checking Twitter for: {USERNAME}")
try:
    r = requests.get(f"https://twitter.com/{USERNAME}", headers={
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
        ])
    }, timeout=15, allow_redirects=True)
    if r.status_code == 200:
        results["exists"] = True
        # Extract profile info
        title_match = re.search(r'<title>(.*?)</title>', r.text, re.I)
        if title_match:
            results["profile"]["page_title"] = title_match.group(1).strip()
        desc_match = re.search(r'<meta name="description" content="(.*?)"', r.text, re.I)
        if desc_match:
            results["profile"]["bio"] = desc_match.group(1)[:500]
        results["profile"]["url"] = f"https://twitter.com/{USERNAME}"
except Exception as e:
    results["errors"].append(f"Profile check error: {str(e)}")

# --- snscrape profile extraction ---
print("[*] Running snscrape user scan...")
try:
    # Profile info
    p = subprocess.run(
        ["snscrape", "--jsonl", f"twitter-user:{USERNAME}"],
        capture_output=True, text=True, timeout=60
    )
    if p.stdout:
        for line in p.stdout.strip().splitlines():
            try:
                d = json.loads(line)
                if "profile" in d.get("_type", "") or "user" in d.get("_type", ""):
                    results["profile"].update({
                        "followers_count": d.get("followersCount"),
                        "following_count": d.get("followingCount"),
                        "tweet_count": d.get("tweetCount"),
                        "listed_count": d.get("listedCount"),
                        "created": d.get("created"),
                        "description": (d.get("description") or "")[:500],
                        "verified": d.get("verified"),
                        "location": d.get("location"),
                        "url": d.get("link"),
                        "profile_image": d.get("profileImageUrl"),
                    })
                    results["exists"] = True
                else:
                    results["recent_tweets"].append({
                        "url": d.get("url"),
                        "date": d.get("date"),
                        "content": (d.get("rawContent") or "")[:300],
                        "like_count": d.get("likeCount"),
                        "retweet_count": d.get("retweetCount"),
                        "reply_count": d.get("replyCount"),
                        "quote_count": d.get("quoteCount"),
                    })
                if len(results["recent_tweets"]) >= 15:
                    break
            except json.JSONDecodeError:
                pass
except Exception as e:
    results["errors"].append(f"snscrape user error: {str(e)}")

# --- Search for mentions ---
print("[*] Searching for mentions...")
try:
    p = subprocess.run(
        ["snscrape", "--jsonl", f"--max-results=20", f"twitter-search:@{USERNAME}"],
        capture_output=True, text=True, timeout=60
    )
    if p.stdout:
        for line in p.stdout.strip().splitlines()[:10]:
            try:
                d = json.loads(line)
                results["mentions"].append({
                    "url": d.get("url"),
                    "date": d.get("date"),
                    "content": (d.get("rawContent") or "")[:300],
                    "user": d.get("user", {}).get("username", "") if isinstance(d.get("user"), dict) else d.get("user"),
                })
            except json.JSONDecodeError:
                pass
except Exception as e:
    results["errors"].append(f"Mention search error: {str(e)}")

# --- Search for username across Twitter ---
search_queries = [
    f'"{USERNAME}" -is:retweet',
    f'from:{USERNAME} -is:retweet',
    f'"{USERNAME}" filter:media',
]

for q in search_queries:
    try:
        p = subprocess.run(
            ["snscrape", "--jsonl", "--max-results=10", f"twitter-search:{q}"],
            capture_output=True, text=True, timeout=45
        )
        if p.stdout:
            for line in p.stdout.strip().splitlines()[:5]:
                try:
                    d = json.loads(line)
                    results["search_results"].append({
                        "query": q,
                        "url": d.get("url"),
                        "content": (d.get("rawContent") or "")[:200],
                        "user": d.get("user", {}).get("username", "") if isinstance(d.get("user"), dict) else str(d.get("user", "")),
                    })
                except json.JSONDecodeError:
                    pass
        time.sleep(2)
    except Exception as e:
        continue

with open(os.path.join(OUT_DIR, "twitter_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({"exists": results["exists"], "tweets": len(results["recent_tweets"]), "mentions": len(results["mentions"])}))