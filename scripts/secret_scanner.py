#!/usr/bin/env python3
"""
Secret Scanner Pipeline — Trufflehog-style secret detection across
GitHub repos, pastebins, and web sources. Supports Persian/Iranian
patterns: Iranian bank cards, national codes (کد ملی), شماره شناسنامه.

Requires:
- requests
- tqdm (optional)
"""
import sys, json, os, re, time, requests, random

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {
    "target": TARGET,
    "secrets": [],
    "github_secrets": [],
    "pastebin_leaks": [],
    "persian_patterns_found": [],
    "errors": []
}

SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "SocialRecon-SecretScanner",
}

# --- Secret Patterns ---
SECRET_PATTERNS = [
    # Generic secrets
    (r'(?i)(aws_access_key_id\s*[:=]\s*)([A-Z0-9]{20})', 'AWS Access Key ID'),
    (r'(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{40})', 'AWS Secret Access Key'),
    (r'(?i)(sk-[a-zA-Z0-9]{20,})', 'OpenAI API Key'),
    (r'(?i)(sk-proj-[a-zA-Z0-9\-]{20,})', 'OpenAI Project Key'),
    (r'(?i)(ghp_[a-zA-Z0-9]{36})', 'GitHub PAT'),
    (r'(?i)(gho_[a-zA-Z0-9]{36})', 'GitHub OAuth Token'),
    (r'(?i)(ghu_[a-zA-Z0-9]{36})', 'GitHub User Token'),
    (r'(?i)(ghs_[a-zA-Z0-9]{36})', 'GitHub Server Token'),
    (r'(?i)(github_pat_[a-zA-Z0-9_]{22,})', 'GitHub Fine-grained PAT'),
    (r'(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)', 'SSH/RSA Private Key Header'),
    (r'(?i)(xox[baprs]-[a-zA-Z0-9\-]{10,})', 'Slack Token'),
    (r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})', 'JWT Token'),
    (r'(?i)(postgres(?:ql)?://[^\s"\']+:[^\s"\']+@)', 'PostgreSQL Connection String'),
    (r'(?i)(mongodb(\+srv)?://[^\s"\']+:[^\s"\']+@)', 'MongoDB Connection String'),
    (r'(?i)(mysql://[^\s"\']+:[^\s"\']+@)', 'MySQL Connection String'),
    (r'(?i)(redis://[^\s"\']+)', 'Redis URL'),
    (r'(?i)(password\s*[:=]\s*)([^\s"\'<]{4,64})', 'Password Field'),
    (r'(?i)(api_key\s*[:=]\s*)([a-zA-Z0-9_\-]{10,64})', 'API Key Field'),
    (r'(?i)(secret\s*[:=]\s*)([a-zA-Z0-9_\-]{10,64})', 'Secret Field'),

    # --- Persian/Iranian patterns ---
    (r'(\b\d{16}\b)', 'Iranian Bank Card Number (16 digits)'),
    (r'(?i)(کد ملی|کدملی|national ?code)[\s:]+(\d{10})', 'کد ملی (National ID)'),
    (r'(?i)(کد شناسنامه|شماره شناسنامه)[\s:]+(\d{10,15})', 'شماره شناسنامه'),
    (r'(?i)(شماره شناسنامه)[\s:]+(\d{10})', 'شماره شناسنامه'),
    (r'(?i)(بیمه)[\s:]+(\d{10})', 'شماره بیمه'),
    (r'(\b\d{10}\b)(?=.*(?:کد ملی|mellicode|national))', 'کد ملی (in JSON field)'),
    (r'(?i)(cvv2?)[\s:]+(\d{3,4})', 'CVV2'),
    (r'(?i)(شماره فیش پرداخت|receipt)[\s:]+(\w{16,20})', 'شماره فیش پرداخت'),
    (r'(?i)(تاریخ انقضا|expiry|exp)[\s:]+(\d{2}/\d{2})', 'تاریخ انقضا کارت'),
    (r'(?i)(رمز دوم|password)[\s:]+(\d{4,6})', 'رمز دوم کارت بانکی'),
    (r'(?i)((?:09|۰۹)\d{9})', 'شماره موبایل ایرانی'),
    (r'(?i)(کارت|card)[\s:]+(\d{16})', 'شماره کارت بانکی'),
    (r'(?i)(شماره قرض‌الحسنه|قرض‌الحسنه|قرض الحسنه)[\s:]+(\d{16})', 'قرض‌الحسنه'),

    # Persian crypto patterns
    (r'(TRX|Tether|BTC|ETH|USDT|USDC)(?:[\s_]*[=:]\s*|)([13][a-zA-Z0-9]{25,}|0x[a-fA-F0-9]{40}|T[a-zA-Z0-9]{33})', 'Cryptocurrency Address'),

    # Iranian payment gateway patterns
    (r'(?i)(آی‌دی فروشگاه|merchant)[\s:]+([a-zA-Z0-9\-_]{16,})', 'Merchant ID'),
    (r'(?i)(تراکنش|transaction)[\s:]+(\w{20,})', 'Transaction ID'),
]

def scan_text(text, source):
    """Scan text for secrets using all patterns."""
    found = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, text)
        for m in matches:
            if isinstance(m, tuple):
                # Extract the secret value (last group)
                secret_val = m[-1]
                if len(secret_val) < 2:
                    continue
            else:
                secret_val = m
            if len(secret_val) > 2:
                found.append({
                    "type": label,
                    "value": secret_val[:50],
                    "source": source,
                })
    return found

# --- GitHub Repo Secret Scanning ---
print(f"[*] Scanning GitHub repos for target: {TARGET}")

# Get user's repos
try:
    r = requests.get(f"https://api.github.com/users/{TARGET}/repos",
                     params={"per_page": 100, "sort": "updated"},
                     headers=headers, timeout=15)
    if r.status_code == 200:
        repos = r.json()
        for repo in repos[:30]:
            repo_name = repo.get("full_name", "")
            print(f"  [*] Scanning: {repo_name}")
            # Search for patterns in repo files
            try:
                # Get default branch
                default_branch = repo.get("default_branch", "main")
                # Try to get file tree
                tree_r = requests.get(
                    f"https://api.github.com/repos/{repo_name}/git/trees/{default_branch}?recursive=1",
                    headers=headers, timeout=10
                )
                if tree_r.status_code == 200:
                    tree = tree_r.json()
                    for item in tree.get("tree", [])[:100]:
                        if item.get("type") == "blob" and item.get("path", "").endswith((".env", ".py", ".js", ".json", ".yml", ".yaml", ".txt", ".config")):
                            # Fetch raw file
                            file_url = f"https://raw.githubusercontent.com/{repo_name}/{default_branch}/{item['path']}"
                            try:
                                fr = requests.get(file_url, headers=headers, timeout=5)
                                if fr.status_code == 200 and len(fr.text) < 500000:
                                    secrets = scan_text(fr.text, f"github:{repo_name}/{item['path']}")
                                    results["secrets"].extend(secrets)
                                    results["github_secrets"].extend(secrets)
                            except Exception:
                                pass
                time.sleep(1)
            except Exception as e:
                results["errors"].append(f"Repo scan error ({repo_name}): {str(e)[:100]}")
    elif r.status_code == 403:
        results["errors"].append("GitHub API rate limit")
except Exception as e:
    results["errors"].append(f"GitHub repos error: {str(e)}")

# --- Search GitHub for target (code search) ---
search_queries = [
    f'"{TARGET}" extension:env',
    f'"{TARGET}" filename:.env',
    f'"{TARGET}" extension:yml OR extension:yaml',
    f'"{TARGET}" extension:json',
    f'"{TARGET}" "password"',
    f'"{TARGET}" "api_key" OR "apikey"',
    f'"{TARGET}" "secret"',
    f'@"{TARGET}" OR "{TARGET}@',
]

for q in search_queries[:5]:
    try:
        r = requests.get("https://api.github.com/search/code",
                         params={"q": q, "per_page": 10},
                         headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                file_url = item.get("html_url", "")
                raw_url = file_url.replace("github.com/", "raw.githubusercontent.com/").replace("/blob/", "/")
                try:
                    fr = requests.get(raw_url, headers=headers, timeout=10)
                    if fr.status_code == 200:
                        secrets = scan_text(fr.text, f"github_search:{item.get('repository', {}).get('full_name', '')}/{item.get('path', '')}")
                        results["secrets"].extend(secrets)
                        results["github_secrets"].extend(secrets)
                except Exception:
                    pass
        time.sleep(1.5)
    except Exception:
        pass

# --- Pastebin/Dump Monitoring ---
print("[*] Checking pastebin and dumps...")
pastebin_sources = [
    ("https://scrape.pastebin.com/api_scraping.php", f"q={TARGET}"),
]

# Use DuckDuckGo to find paste/dump mentions
ddg_queries = [
    f'"{TARGET}" site:pastebin.com',
    f'"{TARGET}" site:ghostbin.com',
    f'"{TARGET}" site:hastebin.com',
    f'"{TARGET}" site:0bin.net',
    f'"{TARGET}" "leak" OR "هک" OR "دیتابیس"',
]

for q in ddg_queries[:3]:
    try:
        r = requests.get("https://html.duckduckgo.com/html/",
                         params={"q": q},
                         headers={"User-Agent": random.choice([
                             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                         ])},
                         timeout=12)
        if r.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            for i, l in enumerate(links[:5]):
                snip = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')
                # Check if this is a paste/dump
                if any(domain in l for domain in ["pastebin", "ghostbin", "hastebin", "0bin"]):
                    try:
                        pr = requests.get(l, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                        if pr.status_code == 200:
                            secrets = scan_text(pr.text, f"pastebin:{l}")
                            results["secrets"].extend(secrets)
                            results["pastebin_leaks"].append({"url": l, "snippet": snip[:200], "secrets_found": len(secrets)})
                    except Exception:
                        pass
        time.sleep(1.5)
    except Exception:
        pass

# --- Persian-specific leak check ---
# Check Iranian dump sites
iranian_dump_sites = [
    "https://www.iadb.ir/",
    "https://iranleaks.xyz/",
]

# Dedup secrets
seen = set()
unique_secrets = []
for s in results["secrets"]:
    key = (s["type"], s["value"])
    if key not in seen:
        seen.add(key)
        unique_secrets.append(s)
        if "Iranian" in s["type"] or "کد ملی" in s["type"] or "Bank Card" in s["type"] or "شماره" in s["type"]:
            results["persian_patterns_found"].append(s)

results["secrets"] = unique_secrets
results["total_secrets"] = len(unique_secrets)
results["total_persian_patterns"] = len(results["persian_patterns_found"])

with open(os.path.join(OUT_DIR, "secret_scan_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({
    "total_secrets": len(results["secrets"]),
    "github_secrets": len(results["github_secrets"]),
    "pastebin_leaks": len(results["pastebin_leaks"]),
    "persian_patterns": len(results["persian_patterns_found"]),
    "secret_types": list(set(s["type"] for s in results["secrets"]))[:10],
    "persian_types": list(set(s["type"] for s in results["persian_patterns_found"]))[:10]
}))