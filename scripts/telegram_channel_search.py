#!/usr/bin/env python3
"""
telegram_channel_search.py — Discover and scan public Telegram channels/groups
for mentions of the target username/email/name.
Uses t.me/s/ endpoint (web archive of public chat history).
"""
import sys, json, os, re, time, random, requests
from urllib.parse import quote

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {"target": TARGET, "channels_found": [], "messages_found": [], "mentions_found": [], "links_found": []}

def fetch_tme(username):
    """Fetch public channel/group info from t.me/s/"""
    try:
        r = requests.get(f"https://t.me/s/{username}", headers={"User-Agent": "Mozilla/5.0"}, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            return r.text, r.url
        return None, None
    except:
        return None, None

def extract_mentions(text, username):
    """Extract mentions, links, emails from text"""
    found = {
        "mentions": re.findall(f'@({username}[^\\s,.!?)\'"»«؟)]*)', text, re.IGNORECASE),
        "emails": re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text),
        "links": re.findall(r'https?://[^\s]+', text),
        "phones": re.findall(r'[\+]?[\d]{3,}[-\s\d]{6,}', text),
    }
    return found

# --- Step 1: Try to find public channels mentioning target ---
search_terms = [
    f"{TARGET}",
    f"@{TARGET}",
    f"{TARGET} site:t.me",
    f'"{TARGET}" تلگرام',
]

queries = [
    f'"{TARGET}" site:t.me',
    f'telegram "{TARGET}"',
    f'"{TARGET}" کانال',
    f'"{TARGET}" گروه',
]

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}

for q in queries[:4]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": q}, headers=UA, timeout=10)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for l in links:
                if "t.me" in l:
                    # Extract channel username
                    m = re.search(r't\.me/s?/([^/\?]+)', l)
                    if m:
                        ch = m.group(1)
                        if ch not in [c.get("username") for c in results["channels_found"]]:
                            results["channels_found"].append({"username": ch, "source": q})
            for s in snippets:
                s = re.sub(r'<[^>]+>', '', s)
                mentions = extract_mentions(s, TARGET)
                if any(mentions.values()):
                    results["mentions_found"].append({"query": q[:40], "text": s[:200]})
        time.sleep(random.uniform(1.5, 2.5))
    except Exception as e:
        pass

# --- Step 2: Fetch messages from found channels ---
for ch in results["channels_found"][:5]:
    uname = ch["username"]
    text, url = fetch_tme(uname)
    if text:
        results["messages_found"].append({"channel": uname, "url": url, "length": len(text)})
        # Search for target mentions in channel messages
        for m in re.finditer(f'.{{0,100}}{re.escape(TARGET)}.{{0,100}}', text, re.IGNORECASE):
            snippet = m.group(0)
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            if any(kw in snippet.lower() for kw in ["@" + TARGET.lower(), TARGET.lower()]):
                results["mentions_found"].append({
                    "channel": uname, "context": snippet[:250]
                })
                # Extract links/emails/phones from snippet
                extracted = extract_mentions(snippet, uname)
                for et, items in extracted.items():
                    if items:
                        results["links_found"].extend(items)

# --- Step 3: Search on known Persian channels ---
persian_channels = [
    "ir_osintschool", "F2Codes", "EasyIDFaBot", "HermesAgent", "NousResearch",
    "erfanashouri", "Erfix404", "iran_osint", "iransec", "cyberdef_ir",
]
for pc in persian_channels[:8]:
    try:
        r = requests.get(f"https://t.me/s/{pc}", headers=UA, timeout=10)
        if r.status_code == 200:
            m = re.search(rf'.{{0,150}}{re.escape(TARGET)}.{{0,150}}', r.text, re.IGNORECASE)
            if m:
                snippet = re.sub(r'<[^>]+>', '', m.group(0)).strip()
                results["mentions_found"].append({"channel": pc, "context": snippet[:250]})
        time.sleep(random.uniform(0.5, 1.0))
    except Exception:
        pass

with open(os.path.join(OUT_DIR, "tg_channel_search_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] Telegram channel scan done.")
print(f"[+] Channels checked: {len(results['channels_found'])}")
print(f"[+] Mentions found: {len(results['mentions_found'])}")
print(f"[+] Links/emails/phones extracted: {len(results['links_found'])}")
print(json.dumps(results))