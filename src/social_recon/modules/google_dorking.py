"""Google Dorking module — automated dork execution via DuckDuckGo and Google CSE."""
import asyncio
import re
import time
import random

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


# Pre-built dork templates
DORK_TEMPLATES = {
    "username": [
        '"{target}" site:instagram.com',
        '"{target}" site:twitter.com OR site:x.com',
        '"{target}" site:linkedin.com',
        '"{target}" site:reddit.com',
        '"{target}" site:github.com',
        '"{target}" site:medium.com',
        '"{target}" site:t.me OR site:telegram.me',
        '"{target}" site:virgool.io',
        '"{target}" site:aparat.com',
        '"{target}" filetype:pdf',
        '"{target}" filetype:doc OR filetype:docx',
        '"{target}" filetype:xlsx',
    ],
    "email": [
        '"{target}" site:github.com',
        '"{target}" site:pastebin.com',
        '"{target}" site:linkedin.com',
        '"{target}" filetype:sql',
        '"{target}" filetype:log',
        '"{target}" "password" OR "passwd" OR "pass"',
        '"{target}" site:facebook.com',
    ],
    "phone": [
        '"{target}" site:divar.ir',
        '"{target}" site:sheypoor.com',
        '"{target}" site:instagram.com',
        '"{target}" site:t.me OR site:telegram.me',
        '"{target}" موبایل OR موبایل',
        '"{target}" site:hamijar.ir OR site:jobinja.ir',
        '"{target}" whatsapp',
    ],
    "domain": [
        'site:{target} filetype:php',
        'site:{target} filetype:env',
        'site:{target} filetype:sql',
        'site:{target} filetype:log',
        'site:{target} inurl:admin',
        'site:{target} inurl:login',
        'site:{target} intitle:"index of"',
        '"{target}" "password" filetype:conf',
        '"{target}" "api_key" OR "apikey" OR "api-key"',
        '"{target}" site:pastebin.com',
        '"{target}" site:github.com',
    ],
}

# Persian dork patterns for Iranian targets
PERSIAN_DORKS = {
    "username": [
        '"{target}" شماره تماس',
        '"{target}" آدرس',
        '"{target}" کد ملی',
        '"{target}" site:divar.ir',
        '"{target}" site:sheypoor.ir',
    ],
    "phone": [
        '"{target}" site:divar.ir',
        '"{target}" site:sheypoor.ir',
        '"{target}" آگهی',
        '"{target}" فروش',
    ],
}


class GoogleDorking(BaseModule):
    """Automated Google Dorking for OSINT — uses DuckDuckGo as backend."""

    name = "google_dorking"
    category = ModuleCategory.ENRICHMENT
    description = "Automated search dorking for discovering leaked data and public information"
    supported_input_types = ["username", "email", "phone", "domain"]

    def __init__(self, config=None):
        super().__init__(config)
        self.max_dorks = (config or {}).get("max_dorks", 20)

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Collect additional targets from context
        extra_targets = []
        if context:
            for email in context.get("emails", [])[:2]:
                if email != target and "noreply" not in email:
                    extra_targets.append(("email", email))
            for phone in context.get("phones", [])[:1]:
                if phone != target:
                    extra_targets.append(("phone", phone))

        # Build dork list
        dorks = self._build_dorks(target, target_type)

        # Add dorks for discovered emails/phones
        for etype, evalue in extra_targets:
            dorks.extend(self._build_dorks(evalue, etype)[:5])

        # Limit total dorks
        dorks = dorks[:self.max_dorks]

        async with self.create_client() as client:
            results = await asyncio.gather(
                *[self._execute_dork(client, dork, target) for dork in dorks],
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    errors.append(str(result))

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    def _build_dorks(self, target: str, target_type: str) -> list[str]:
        """Build dork queries for the target."""
        templates = DORK_TEMPLATES.get(target_type, DORK_TEMPLATES["username"])
        dorks = [t.format(target=target) for t in templates]

        # Add Persian dorks for Iranian targets
        persian_templates = PERSIAN_DORKS.get(target_type, [])
        dorks.extend([t.format(target=target) for t in persian_templates])

        return dorks

    async def _execute_dork(self, client: httpx.AsyncClient, dork: str, original_target: str) -> list[Finding]:
        """Execute a single dork via DuckDuckGo HTML."""
        findings = []

        # Rate limiting: random delay between dorks
        await asyncio.sleep(random.uniform(1.0, 2.5))

        resp = await self._make_request(
            client, "GET",
            "https://html.duckduckgo.com/html/",
            params={"q": dork},
        )

        if not resp or resp.status_code != 200:
            return findings

        text = resp.text

        # Extract search results
        result_blocks = re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?class="result__snippet"[^>]*>(.*?)</(?:a|div)',
            text,
            re.DOTALL,
        )

        for url, title, snippet in result_blocks[:5]:
            if "duckduckgo.com" in url:
                continue

            # Clean HTML tags
            title = re.sub(r'<[^>]+>', '', title).strip()
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()

            # Skip if URL contains DDG redirect
            if "duckduckgo.com/l/" in url:
                # Extract actual URL from redirect
                actual = re.search(r'uddg=([^&]+)', url)
                if actual:
                    import urllib.parse
                    url = urllib.parse.unquote(actual.group(1))

            if not url or "duckduckgo.com" in url:
                continue

            # Calculate confidence based on relevance
            confidence = 0.4
            url_lower = url.lower()
            snippet_lower = snippet.lower()
            target_lower = original_target.lower()

            if target_lower in url_lower:
                confidence = 0.7
            if target_lower in snippet_lower:
                confidence = max(confidence, 0.6)

            # Higher confidence for sensitive findings
            sensitive_patterns = ["password", "api_key", "secret", "token", "passwd", "credential"]
            if any(p in snippet_lower for p in sensitive_patterns):
                confidence = 0.8

            findings.append(Finding(
                source="google_dork",
                data_type="search_hit",
                value={
                    "query": dork[:100],
                    "url": url,
                    "title": title[:200],
                    "snippet": snippet[:300],
                },
                confidence=confidence,
                metadata={
                    "type": "dork_result",
                    "dork": dork[:80],
                },
            ))

        return findings
