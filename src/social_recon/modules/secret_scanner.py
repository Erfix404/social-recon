"""Secret scanner — finds API keys, tokens, and credentials in public code/data."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


# Regex patterns for common secrets
SECRET_PATTERNS = {
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "github_oauth": r"gho_[A-Za-z0-9]{36}",
    "github_app_token": r"(ghu|ghs)_[A-Za-z0-9]{36}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "slack_token": r"xox[bporas]-[0-9A-Za-z\-]+",
    "slack_webhook": r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "stripe_key": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    "telegram_bot_token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    "heroku_api_key": r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "sendgrid_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "mailgun_key": r"key-[0-9a-zA-Z]{32}",
    "twilio_sid": r"AC[a-f0-9]{32}",
    "twilio_token": r"(?i)twilio.*[a-f0-9]{32}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "generic_api_key": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})",
    "generic_password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
    "generic_secret": r"(?i)(secret|token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})",
    "ip_address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "iranian_national_id": r"\b\d{10}\b",  # کد ملی — 10 digits
    "iranian_bank_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # شماره کارت
    "iranian_sheba": r"\bIR\d{24}\b",  # شبا
}

# Persian-specific patterns
PERSIAN_SECRET_PATTERNS = {
    "mobile_number": r"(?:\+98|0)?\s?9\d{2}[\s\-]?\d{3}[\s\-]?\d{4}",
    "national_id": r"(?:کد\s*ملی|شناسه\s*ملی)[:\s]*(\d{10})",
    "bank_card": r"(?:شماره\s*کارت|کارت\s*بانکی)[:\s]*(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})",
    "sheba": r"(?:شبا|IBAN)[:\s]*(IR\d{24})",
}


class SecretScanner(BaseModule):
    """Scan GitHub repos, gists, and public data for leaked secrets."""

    name = "secret_scanner"
    category = ModuleCategory.BREACH
    description = "Find API keys, tokens, credentials, and Iranian PII in public code"
    supported_input_types = ["username", "email", "domain"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target_clean = target.replace("@", "").strip()

        async with self.create_client() as client:
            # Run all scanning tasks concurrently
            results = await asyncio.gather(
                self._scan_github_repos(client, target_clean),
                self._scan_github_gists(client, target_clean),
                self._scan_github_search(client, target_clean),
                self._scan_pastes(client, target_clean),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    errors.append(str(result))

        # Deduplicate by value
        seen = set()
        unique_findings = []
        for f in findings:
            key = str(f.value)[:100]
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=unique_findings,
            errors=errors,
        )

    def _scan_text_for_secrets(self, text: str, source: str) -> list[Finding]:
        """Scan a text blob for secret patterns."""
        findings = []

        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group(0)
                # Filter out obvious false positives
                if secret_type == "ip_address":
                    if value.startswith(("0.", "127.", "255.", "10.", "192.168.", "172.16.")):
                        continue
                if secret_type == "iranian_national_id":
                    # Must be exactly 10 digits and not all same digit
                    if len(set(value)) < 3:
                        continue

                # Redact middle of sensitive values
                if len(value) > 16 and secret_type not in ("ip_address", "iranian_national_id"):
                    display = value[:8] + "..." + value[-4:]
                else:
                    display = value

                confidence = 0.8
                if secret_type in ("github_token", "aws_access_key", "private_key", "jwt_token"):
                    confidence = 0.95
                elif secret_type.startswith("generic"):
                    confidence = 0.4

                findings.append(Finding(
                    source=f"secret_scan:{source}",
                    data_type="secret",
                    value={
                        "type": secret_type,
                        "value": display,
                        "raw_length": len(value),
                        "source": source,
                    },
                    confidence=confidence,
                    metadata={"secret_type": secret_type, "source": source},
                ))

        # Persian patterns
        for ptype, pattern in PERSIAN_SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group(1) if match.groups() else match.group(0)
                findings.append(Finding(
                    source=f"secret_scan:{source}",
                    data_type="secret",
                    value={
                        "type": f"iranian_{ptype}",
                        "value": value,
                        "source": source,
                    },
                    confidence=0.7,
                    metadata={"secret_type": f"iranian_{ptype}", "source": source},
                ))

        return findings

    async def _scan_github_repos(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Scan user's public GitHub repos for secrets."""
        findings = []

        # Get user's repos
        resp = await self._make_request(
            client, "GET",
            f"https://api.github.com/users/{username}/repos",
            params={"per_page": 30, "sort": "updated"},
            headers={"Accept": "application/vnd.github+json"},
        )
        if not resp or resp.status_code != 200:
            return findings

        repos = resp.json()
        if not isinstance(repos, list):
            return findings

        # Scan common secret-containing files in each repo
        secret_files = [".env", ".env.example", ".env.local", "config.py", "config.json",
                        "settings.py", "credentials.json", "docker-compose.yml", ".htaccess"]

        for repo in repos[:10]:
            repo_name = repo.get("full_name", "")
            default_branch = repo.get("default_branch", "main")

            # Check for common secret files
            for filename in secret_files:
                file_resp = await self._make_request(
                    client, "GET",
                    f"https://raw.githubusercontent.com/{repo_name}/{default_branch}/{filename}",
                    timeout=8,
                )
                if file_resp and file_resp.status_code == 200:
                    content = file_resp.text[:50000]  # Limit to 50KB
                    file_findings = self._scan_text_for_secrets(
                        content, f"github:{repo_name}/{filename}",
                    )
                    findings.extend(file_findings)

            # Also scan repo description and README for patterns
            desc = repo.get("description", "") or ""
            if desc:
                desc_findings = self._scan_text_for_secrets(desc, f"github:{repo_name}/description")
                findings.extend(desc_findings)

            await asyncio.sleep(0.5)  # Rate limiting

        return findings

    async def _scan_github_gists(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Scan user's public gists for secrets."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            f"https://api.github.com/users/{username}/gists",
            params={"per_page": 30},
            headers={"Accept": "application/vnd.github+json"},
        )
        if not resp or resp.status_code != 200:
            return findings

        gists = resp.json()
        if not isinstance(gists, list):
            return findings

        for gist in gists[:15]:
            gist_id = gist.get("id", "")
            for filename, file_info in gist.get("files", {}).items():
                raw_url = file_info.get("raw_url", "")
                if not raw_url:
                    continue

                file_resp = await self._make_request(client, "GET", raw_url, timeout=8)
                if file_resp and file_resp.status_code == 200:
                    content = file_resp.text[:50000]
                    gist_findings = self._scan_text_for_secrets(
                        content, f"gist:{gist_id}/{filename}",
                    )
                    findings.extend(gist_findings)

            await asyncio.sleep(0.3)

        return findings

    async def _scan_github_search(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Search GitHub code for mentions of the username with secrets."""
        findings = []

        queries = [
            f'"{username}" password OR secret OR token OR api_key',
            f'"{username}" filetype:env',
        ]

        for query in queries[:2]:
            resp = await self._make_request(
                client, "GET",
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 10},
                headers={"Accept": "application/vnd.github+json"},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:5]:
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    findings.append(Finding(
                        source="github_search",
                        data_type="secret",
                        value={
                            "type": "code_mention",
                            "repo": repo,
                            "path": path,
                            "url": item.get("html_url", ""),
                            "query": query[:50],
                        },
                        confidence=0.5,
                        metadata={"type": "github_code_search"},
                    ))
            await asyncio.sleep(1)

        return findings

    async def _scan_pastes(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Search paste sites for the target."""
        findings = []

        # DuckDuckGo search for paste sites
        queries = [
            f'site:pastebin.com "{username}"',
            f'site:dpaste.org "{username}"',
            f'"{username}" "password" OR "leak" OR "dump" site:pastebin.com',
        ]

        for query in queries[:2]:
            resp = await self._make_request(
                client, "GET",
                "https://html.duckduckgo.com/html/",
                params={"q": query},
            )
            if resp and resp.status_code == 200:
                links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', resp.text)
                snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', resp.text, re.DOTALL)

                for i, link in enumerate(links[:3]):
                    if "duckduckgo.com" not in link:
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:150]
                        findings.append(Finding(
                            source="paste_search",
                            data_type="secret",
                            value={
                                "type": "paste_mention",
                                "url": link,
                                "snippet": snippet,
                                "query": query[:50],
                            },
                            confidence=0.4,
                            metadata={"type": "paste_result"},
                        ))
            await asyncio.sleep(1)

        return findings
