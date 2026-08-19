"""Telegram OSINT module — deep Telegram reconnaissance."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class TelegramOSINT(BaseModule):
    """Deep Telegram reconnaissance — profile scraping, channel search, group discovery."""

    name = "telegram_osint"
    category = ModuleCategory.SOCIAL
    description = "Telegram profile and channel analysis via t.me scraping and TGStat"
    supported_input_types = ["username", "phone"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            # Run all Telegram checks concurrently
            results = await asyncio.gather(
                self._scrape_tme(client, target),
                self._check_tgstat(client, target),
                self._search_tg_channels(client, target),
                self._check_phone_tg(client, target, target_type, context),
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

    async def _scrape_tme(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Scrape t.me public page for profile info."""
        findings = []

        resp = await self._make_request(client, "GET", f"https://t.me/{username}")
        if not resp or resp.status_code != 200:
            return findings

        text = resp.text

        if "tgme_page_title" not in text:
            return findings

        # Extract profile data
        title = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', text)
        desc = re.search(r'tgme_page_description[^>]*>(.*?)</div>', text, re.DOTALL)
        photo = re.search(r'<img[^>]+src="([^"]+)"[^>]*class="tgme_page_photo_image"', text)
        members = re.search(r'(\d[\d\s,]+)\s*(?:subscriber|member|عضو)', text)
        username_link = re.search(r'tgme_page_extra[^>]*>([^<]+)', text)

        profile = {
            "platform": "telegram",
            "username": username,
            "url": f"https://t.me/{username}",
            "title": title.group(1).strip() if title else None,
            "description": re.sub(r'<[^>]+>', '', desc.group(1)).strip() if desc else None,
            "photo_url": photo.group(1) if photo else None,
            "members": members.group(1).strip().replace(" ", "").replace(",", "") if members else None,
            "extra": username_link.group(1).strip() if username_link else None,
        }

        # Determine if it's a channel, group, or user
        if "channel" in text.lower() or "کانال" in text:
            profile["type"] = "channel"
        elif "group" in text.lower() or "گروه" in text:
            profile["type"] = "group"
        else:
            profile["type"] = "user"

        findings.append(Finding(
            source="telegram:tme",
            data_type="profile",
            value=profile,
            confidence=0.85,
            metadata={"site": "telegram", "method": "tme_scrape"},
        ))

        # Photo as separate finding
        if photo:
            findings.append(Finding(
                source="telegram:tme",
                data_type="image",
                value=photo.group(1),
                confidence=0.9,
                metadata={"site": "telegram", "type": "profile_photo"},
            ))

        return findings

    async def _check_tgstat(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check TGStat for channel statistics."""
        findings = []

        # Try both ir.tgstat.com and tgstat.ru
        for domain in ["ir.tgstat.com", "tgstat.com"]:
            resp = await self._make_request(
                client, "GET",
                f"https://{domain}/channel/@{username}",
            )
            if resp and resp.status_code == 200:
                text = resp.text
                if "channel-title" in text or "channel-header" in text:
                    # Extract stats
                    subscribers = re.search(r'(\d[\d,]*)\s*(?:subscriber|member|دنبال)', text)
                    posts = re.search(r'(\d[\d,]*)\s*(?:post|پست)', text)
                    avg_views = re.search(r'(\d[\d,]*)\s*(?:avg|میانگین).*?(?:view|بازدید)', text)

                    findings.append(Finding(
                        source=f"tgstat:{domain}",
                        data_type="profile",
                        value={
                            "platform": "telegram",
                            "source": "tgstat",
                            "username": username,
                            "url": f"https://{domain}/channel/@{username}",
                            "subscribers": subscribers.group(1).replace(",", "") if subscribers else None,
                            "posts": posts.group(1).replace(",", "") if posts else None,
                            "avg_views": avg_views.group(1).replace(",", "") if avg_views else None,
                        },
                        confidence=0.8,
                        metadata={"site": "tgstat", "method": "web_scrape"},
                    ))
                    break

        return findings

    async def _search_tg_channels(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Search for Telegram channels mentioning the target."""
        findings = []

        # DuckDuckGo search for Telegram mentions
        queries = [
            f'site:t.me "{username}"',
            f'site:telegram.me "{username}"',
            f'"{username}" telegram کانال',
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

                for i, link in enumerate(links[:5]):
                    if "duckduckgo.com" in link:
                        continue
                    if "t.me/" in link or "telegram.me/" in link:
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:150]
                        findings.append(Finding(
                            source="telegram_search",
                            data_type="search_hit",
                            value={
                                "url": link,
                                "snippet": snippet,
                                "query": query,
                            },
                            confidence=0.5,
                            metadata={"type": "telegram_mention"},
                        ))

            await asyncio.sleep(1)

        return findings

    async def _check_phone_tg(self, client: httpx.AsyncClient, target: str, target_type: str, context: dict = None) -> Finding | None:
        """If phone number found, check Telegram for it."""
        phones = []
        if target_type == "phone":
            phones.append(target)
        if context:
            phones.extend(context.get("phones", [])[:2])

        for phone in phones:
            clean = phone.replace("+98", "0").replace(" ", "")
            resp = await self._make_request(client, "GET", f"https://t.me/{clean}")
            if resp and resp.status_code == 200 and "tgme_page_title" in resp.text:
                title = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', resp.text)
                return Finding(
                    source="telegram:phone",
                    data_type="profile",
                    value={
                        "platform": "telegram",
                        "phone": phone,
                        "url": f"https://t.me/{clean}",
                        "title": title.group(1).strip() if title else None,
                    },
                    confidence=0.7,
                    metadata={"site": "telegram", "method": "phone_lookup"},
                )

        return None
