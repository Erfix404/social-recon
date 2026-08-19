#!/usr/bin/env python3
"""
github_code_search.py — Search all PUBLIC GitHub code for any mention 
of the target (username, email, fullname). Uses GitHub REST API v3 (no key).
"""
import sys, json, os, re, time, requests

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
      "Accept": "application/vnd.github+json"}
results = {"target": TARGET, "code_matches": [], "emails_found": [], "user_mentions": [], "repo_mentions": []}

# --- GitHub Code Search (requires auth for high-volume, limited unauth) ---
queries = [
    f"{TARGET} in:file",
    f"{TARGET}@users.noreply.github.com in:file",
    f"{TARGET} extension:txt",
    f"{TARGET} extension:env",
    f"{TARGET} extension:json language:json",
]

for q in queries[:4]:
    try:
        r = requests.get("https://api.github.com/search/code",
                         params={"q": q, "per_page": 10}, headers=UA, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", [])[:10]:
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                url = item.get("html_url", "")
                results["code_matches"].append({
                    "repo": repo, "path": path, "url": url,
                    "query": q
                })
                results["repo_mentions"].append(repo)
            total = data.get("total_count", 0)
            results["code_matches"].append({"query": q, "total_count": total})
        elif r.status_code == 401:
            results["error"] = "GitHub API requires authentication for code search. Add GH_TOKEN."
            # Fallback: search user's public repos for the string
            break
        time.sleep(1.5)
    except Exception as e:
        results["error"] = str(e)
        break

# --- Fallback: Search user's own repos via GitHub API ---
print(f"[*] Searching repos of {TARGET}...")
try:
    rp = requests.get(f"https://api.github.com/users/{TARGET}/repos?per_page=100&type=owner",
                      headers=UA, timeout=15)
    if rp.status_code == 200:
        repos = rp.json()
        results["repos_list"] = [{"name": r.get("name"), "url": r.get("html_url"), "language": r.get("language"), "description": r.get("description")} for r in repos[:30]]
    elif rp.status_code == 404:
        results["repos_list"] = {"error": "No public repos found or user does not exist."}
except Exception as e:
    results["repos_list"] = {"error": str(e)}

# --- Search inside gist content ---
print("[*] Checking public gists...")
try:
    gp = requests.get(f"https://api.github.com/users/{TARGET}/gists",
                      headers=UA, timeout=10)
    if gp.status_code == 200:
        gists = gp.json()
        results["gists"] = [{"id": g.get("id"), "description": g.get("description", ""), "url": g.get("html_url"), "files": list(g.get("files", {}).keys())} for g in gists[:20]]
        for g in gists[:20]:
            for fname, fdata in g.get("files", {}).items():
                content = fdata.get("content", "") or (fdata.get("truncated", False) and "[truncated]")
                emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', content)
                for em in emails:
                    if em.lower() not in [x.lower() for x in results["emails_found"]]:
                        results["emails_found"].append(em)
                matches = re.findall(f'.{{0,80}}{re.escape(TARGET)}.{{0,80}}', content, re.IGNORECASE)
                for m in matches[:5]:
                    results["user_mentions"].append({"file": fname, "context": m.strip()[:200]})
except Exception as e:
    results["gists"] = {"error": str(e)}

# --- Search GitHub issues/PRs for username ---
print("[*] Checking issues/PRs mentioning target...")
try:
    ip = requests.get("https://api.github.com/search/issues",
                      params={"q": f"user:{TARGET}", "per_page": 10}, headers=UA, timeout=10)
    if ip.status_code == 200:
        items = ip.json().get("items", [])[:10]
        results["issues_prs"] = [{"title": i.get("title"), "url": i.get("html_url"), "state": i.get("state"), "created_at": i.get("created_at")} for i in items]
except Exception as e:
    results["issues_prs"] = {"error": str(e)}

with open(os.path.join(OUT_DIR, "github_code_search_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"[+] GitHub search done. Code matches: {len(results.get('code_matches', []))}")
print(f"[+] Repos: {len(results.get('repos_list', [])) if isinstance(results.get('repos_list'), list) else 0}")
print(f"[+] Emails found: {results.get('emails_found', [])}")
print(json.dumps(results))