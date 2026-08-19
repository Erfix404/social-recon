#!/usr/bin/env python3
"""
GitHub Advanced Recon Pipeline — Dorks, Secrets, Commits, Gists, Issues.
Uses GitHub REST API and graphql for deep GitHub reconnaissance.

Features:
- GitHub Dorking (search code with known sensitive patterns)
- Git-secrets / trufflehog style search via GitHub code search
- Commit history analysis (email harvesting)
- Gists enumeration (public + search)
- Issues/PR mentioning target
- Repo cloner for offline analysis (optional)
- GitHub organization/user follower graph
"""
import sys, json, os, re, time, requests, random

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {
    "target": TARGET,
    "code_matches": [],
    "emails_found": [],
    "repo_secrets": [],
    "commit_emails": [],
    "gists": [],
    "issues_prs": [],
    "org_members": [],
    "follower_graph": [],
    "errors": []
}

# --- GitHub API tokens (optional, avoids rate limits) ---
GH_TOKEN = os.environ.get("GH_TOKEN", "")
headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}
if GH_TOKEN:
    headers["Authorization"] = f"Bearer {GH_TOKEN}"

# --- GitHub Dorks ---
print(f"[*] Running GitHub dorks on: {TARGET}")
dorks = [
    f'"{TARGET}" in:file',
    f'{TARGET}@users.noreply.github.com in:file',
    f'"{TARGET}" extension:env',
    f'"{TARGET}" extension:json language:json',
    f'"{TARGET}" filename:.env',
    f'"{TARGET}" filename:id_rsa OR filename:.ssh',
    f'"{TARGET}" filename:secrets.txt',
    f'"{TARGET}" path:credentials',
    f'"{TARGET}" path:secrets',
    f'"{TARGET}" extension:pem',
    f'"{TARGET}" extension:key',
    f'"{TARGET}" filename:*.yml OR filename:*.yaml',
    f'"{TARGET}" extension:sql',
    f'"{TARGET}" extension:log',
    f'"{TARGET}" intitle:"index of"',
]

for q in dorks[:10]:
    try:
        r = requests.get("https://api.github.com/search/code",
                         params={"q": q, "per_page": 10},
                         headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                results["code_matches"].append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "dork": q
                })
                # Extract emails from file
                file_url = item.get("html_url", "")
                if file_url:
                    raw_url = file_url.replace("github.com/", "raw.githubusercontent.com/").replace("/blob/", "/")
                    try:
                        rf = requests.get(raw_url, headers=headers, timeout=10)
                        if rf.status_code == 200:
                            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', rf.text)
                            for em in emails:
                                if em.lower() not in [e.lower() for e in results["emails_found"]]:
                                    results["emails_found"].append(em)
                            # Look for secrets
                            secret_patterns = [
                                (r'(?i)(aws_access_key_id\s*=\s*)([A-Z0-9]{20})', 'AWS Access Key'),
                                (r'(?i)(aws_secret_access_key\s*=\s*)([A-Za-z0-9/+=]{40})', 'AWS Secret Key'),
                                (r'(?i)sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
                                (r'(?i)ghp_[a-zA-Z0-9]{36}', 'GitHub PAT'),
                                (r'(?i)gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
                                (r'(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----', 'Private Key Block'),
                            ]
                            file_content = rf.text[:5000]
                            for pattern, label in secret_patterns:
                                matches = re.findall(pattern, file_content)
                                for m in matches:
                                    if isinstance(m, tuple):
                                        val = m[-1]
                                    else:
                                        val = m
                                    results["repo_secrets"].append({
                                        "type": label,
                                        "repo": item.get("repository", {}).get("full_name", ""),
                                        "path": item.get("path", ""),
                                        "value": val[:50],
                                    })
                    except Exception:
                        pass
        elif r.status_code == 403:
            results["errors"].append("GitHub API rate limit exceeded")
            break
        time.sleep(1.5)
    except Exception as e:
        results["errors"].append(f"Dork error ({q[:30]}): {str(e)[:100]}")

# --- GitHub User Commits ---
print("[*] Fetching commit history...")
try:
    r = requests.get(f"https://api.github.com/users/{TARGET}/events/public",
                     headers=headers, params={"per_page": 100}, timeout=15)
    if r.status_code == 200:
        events = r.json()
        for e in events:
            if e.get("type") == "PushEvent":
                for commit in e.get("payload", {}).get("commits", []):
                    msg = commit.get("message", "")
                    # Extract emails from commit messages
                    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', msg)
                    for em in emails:
                        if em not in results["commit_emails"]:
                            results["commit_emails"].append(em)
    time.sleep(1)
except Exception as e:
    results["errors"].append(f"Commit history error: {str(e)}")

# --- Gists ---
print("[*] Fetching public gists...")
try:
    r = requests.get(f"https://api.github.com/users/{TARGET}/gists",
                     headers=headers, params={"per_page": 30}, timeout=15)
    if r.status_code == 200:
        for g in r.json():
            files_info = []
            for fname, fdata in g.get("files", {}).items():
                if fdata and fdata.get("size", 0) < 100000:
                    files_info.append({"name": fname, "size": fdata.get("size")})
            results["gists"].append({
                "id": g.get("id"),
                "description": g.get("description", "")[:200],
                "url": g.get("html_url"),
                "files": files_info,
                "created_at": g.get("created_at"),
            })
except Exception as e:
    results["errors"].append(f"Gist fetch error: {str(e)}")

# --- Search GitHub for the target username ---
print("[*] Searching GitHub users...")
try:
    r = requests.get("https://api.github.com/search/users",
                     params={"q": TARGET, "per_page": 10},
                     headers=headers, timeout=15)
    if r.status_code == 200:
        data = r.json()
        for item in data.get("items", []):
            results["follower_graph"].append({
                "username": item.get("login"),
                "url": item.get("html_url"),
                "score": item.get("score"),
            })
except Exception as e:
    results["errors"].append(f"User search error: {str(e)}")

# --- Check repos for issues/PRs mentioning target ---
print("[*] Checking repos for issues/PRs...")
try:
    r = requests.get(f"https://api.github.com/users/{TARGET}/repos",
                     headers=headers, params={"per_page": 50, "sort": "updated"}, timeout=15)
    if r.status_code == 200:
        repos = r.json()
        for repo in repos[:10]:
            repo_name = repo.get("full_name", "")
            # Search issues
            ri = requests.get(f"https://api.github.com/repos/{repo_name}/issues",
                              params={"state": "all", "per_page": 20},
                              headers=headers, timeout=10)
            if ri.status_code == 200:
                for issue in ri.json():
                    if TARGET.lower() in (issue.get("title", "") + issue.get("body", "")).lower():
                        results["issues_prs"].append({
                            "repo": repo_name,
                            "title": issue.get("title", "")[:100],
                            "url": issue.get("html_url", ""),
                            "state": issue.get("state", ""),
                        })
            time.sleep(0.5)
except Exception as e:
    results["errors"].append(f"Issues/PR check error: {str(e)}")

# --- Check org membership ---
print("[*] Checking org membership...")
try:
    r = requests.get(f"https://api.github.com/users/{TARGET}/orgs",
                     headers=headers, timeout=10)
    if r.status_code == 200:
        for org in r.json():
            results["org_members"].append({
                "org": org.get("login", ""),
                "url": org.get("html_url", ""),
                "role": org.get("role", ""),
            })
except Exception as e:
    results["errors"].append(f"Org membership error: {str(e)}")

with open(os.path.join(OUT_DIR, "github_advanced_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({
    "code_matches": len(results["code_matches"]),
    "emails_from_code": len(results["emails_found"]),
    "commit_emails": len(results["commit_emails"]),
    "gists": len(results["gists"]),
    "issues_prs": len(results["issues_prs"]),
    "orgs": len(results["org_members"]),
    "secrets_found": len(results["repo_secrets"]),
    "users_found": len(results["follower_graph"])
}))