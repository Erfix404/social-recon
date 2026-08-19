"""Email enrichment module — discover accounts and reputation from email."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import HIBP_API_KEY


class EmailEnricher(BaseModule):
    """Enrich email addresses: find associated accounts, check breaches, extract profiles."""

    name = "email_enricher"
    category = ModuleCategory.EMAIL
    description = "Email enrichment — account discovery, reputation, breach check"
    supported_input_types = ["email"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        if target_type != "email":
            return ModuleResult(module_name=self.name, success=False, errors=["Target is not an email"])

        emails_to_check = [target]
        # Also check emails from context
        for e in (context or {}).get("emails", []):
            if e not in emails_to_check and "noreply" not in e:
                emails_to_check.append(e)

        async with self.create_client() as client:
            for email in emails_to_check[:3]:
                # Run all checks concurrently
                results = await asyncio.gather(
                    self._check_emailrep(client, email),
                    self._check_holehe_pattern(client, email),
                    self._extract_from_github(client, email),
                    self._check_gravatar(client, email),
                    self._check_social_from_email(client, email),
                    return_exceptions=True,
                )

                for result in results:
                    if isinstance(result, list):
                        findings.extend(result)
                    elif isinstance(result, Finding):
                        findings.append(result)
                    elif isinstance(result, Exception):
                        errors.append(str(result))

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    async def _check_emailrep(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Check email reputation via EmailRep.io."""
        findings = []
        resp = await self._make_request(client, "GET", f"https://emailrep.io/{email}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                findings.append(Finding(
                    source="emailrep",
                    data_type="email_reputation",
                    value={
                        "email": email,
                        "reputation": data.get("reputation", ""),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "details": data.get("details", {}),
                    },
                    confidence=0.8,
                    metadata={"source": "emailrep"},
                ))

                # Extract profiles from details
                details = data.get("details", {})
                if details.get("profiles"):
                    for profile in details["profiles"]:
                        findings.append(Finding(
                            source="emailrep",
                            data_type="profile",
                            value={"platform": profile, "email": email},
                            confidence=0.7,
                            metadata={"site": profile, "method": "emailrep"},
                        ))

                # Extract name
                if details.get("first_name") or details.get("last_name"):
                    name = f"{details.get('first_name', '')} {details.get('last_name', '')}".strip()
                    if name:
                        findings.append(Finding(
                            source="emailrep",
                            data_type="name",
                            value=name,
                            confidence=0.7,
                            metadata={"source": "emailrep"},
                        ))

            except Exception:
                pass
        return findings

    async def _check_holehe_pattern(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Check email registration across platforms using Holehe-style probing.

        Instead of depending on holehe library, we directly check common sites.
        """
        findings = []
        sites = {
            "twitter": "https://api.twitter.com/users/lookup.json?screen_name={}",
            "github": "https://api.github.com/search/users?q={}+in:email",
            "pinterest": "https://www.pinterest.com/resource/UserResource/get/?data={{}}",
        }

        # GitHub email search (most reliable)
        resp = await self._make_request(
            client, "GET",
            f"https://api.github.com/search/users?q={email}+in:email",
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for user in data.get("items", [])[:3]:
                    findings.append(Finding(
                        source="holehe:github",
                        data_type="profile",
                        value={
                            "platform": "github",
                            "username": user.get("login", ""),
                            "url": user.get("html_url", ""),
                            "avatar": user.get("avatar_url", ""),
                        },
                        confidence=0.9,
                        metadata={"site": "github", "method": "email_search"},
                    ))
            except Exception:
                pass

        return findings

    async def _extract_from_github(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Find GitHub users by searching commit email."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email}", "sort": "committer-date", "order": "desc", "per_page": 10},
            headers={
                "Accept": "application/vnd.github.cloak-preview+json",
                "Accept": "application/vnd.github+json",
            },
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                users_seen = set()
                for item in data.get("items", [])[:10]:
                    author = item.get("author") or {}
                    login = author.get("login", "")
                    if login and login not in users_seen:
                        users_seen.add(login)
                        findings.append(Finding(
                            source="github_commits",
                            data_type="profile",
                            value={
                                "platform": "github",
                                "username": login,
                                "url": f"https://github.com/{login}",
                                "email": email,
                            },
                            confidence=0.85,
                            metadata={"site": "github", "method": "commit_email"},
                        ))

                    # Extract other commit emails
                    commit = item.get("commit", {})
                    for key in ("author", "committer"):
                        ca = commit.get(key, {})
                        if ca.get("email") and ca["email"] != email and "noreply" not in ca["email"]:
                            findings.append(Finding(
                                source="github_commits",
                                data_type="email",
                                value=ca["email"],
                                confidence=0.7,
                                metadata={"source": "github_commit", "related_email": email},
                            ))
            except Exception:
                pass

        return findings

    async def _check_gravatar(self, client: httpx.AsyncClient, email: str) -> Finding | None:
        """Check Gravatar for profile info."""
        import hashlib
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()

        resp = await self._make_request(
            client, "GET",
            f"https://en.gravatar.com/{email_hash}.json",
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json().get("entry", [{}])[0]
                return Finding(
                    source="gravatar",
                    data_type="profile",
                    value={
                        "platform": "gravatar",
                        "display_name": data.get("displayName", ""),
                        "profile_url": data.get("profileUrl", ""),
                        "photos": [p.get("value") for p in data.get("photos", [])],
                        "accounts": [
                            {"service": a.get("shortname", ""), "url": a.get("url", "")}
                            for a in data.get("accounts", [])
                        ],
                        "about": data.get("aboutMe", ""),
                        "location": data.get("currentLocation", ""),
                    },
                    confidence=0.85,
                    metadata={"site": "gravatar", "method": "hash_lookup"},
                )
            except Exception:
                pass
        return None

    async def _check_social_from_email(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Discover social media accounts from email."""
        findings = []
        username = email.split("@")[0]

        # Check common platforms with the email username
        platforms = {
            "instagram": f"https://www.instagram.com/{username}/",
            "twitter": f"https://x.com/{username}",
            "tiktok": f"https://www.tiktok.com/@{username}",
            "linkedin": f"https://www.linkedin.com/in/{username}",
            "reddit": f"https://www.reddit.com/user/{username}",
            "medium": f"https://medium.com/@{username}",
        }

        for platform, url in platforms.items():
            resp = await self._make_request(client, "GET", url)
            if resp and resp.status_code == 200:
                text = resp.text.lower()
                if "not found" not in text and "404" not in text and "page isn't available" not in text:
                    findings.append(Finding(
                        source=f"email_social:{platform}",
                        data_type="profile",
                        value={"platform": platform, "username": username, "url": url},
                        confidence=0.4,  # Low — just because username matches doesn't mean it's the same person
                        metadata={"site": platform, "method": "email_username_probe"},
                    ))

        return findings
