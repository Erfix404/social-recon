"""Community OSINT tricks — real-world techniques shared by researchers.

These are practical tricks discovered and shared by the OSINT community
on Twitter, Reddit, and Telegram channels.
"""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class CommunityTricks(BaseModule):
    """Community-discovered OSINT tricks and techniques."""

    name = "community_tricks"
    category = ModuleCategory.ENRICHMENT
    description = "Real-world OSINT tricks: extra platforms, TgramSearch, Yandex, Google cache"
    supported_input_types = ["username", "email", "phone"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            tasks = [
                self._extra_platforms(client, target),
                self._tgramsearch(client, target),
                self._yandex_dork(client, target),
                self._google_cache_check(client, target),
                self._linktree_beacons(client, target),
                self._telegram_bots_check(client, target),
                self._osint_dorks_collection(client, target, target_type),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Finding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    errors.append(str(result)[:200])

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    # ── Extra Platforms (Maigret might miss) ────────────────────────

    async def _extra_platforms(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check platforms that Maigret might miss."""
        findings = []

        extra_sites = {
            "onlyfans": f"https://onlyfans.com/{username}",
            "linktree": f"https://linktr.ee/{username}",
            "beacons": f"https://beacons.ai/{username}",
            "cashapp": f"https://cash.app/${username}",
            "venmo": f"https://account.venmo.com/u/{username}",
            "spotify": f"https://open.spotify.com/user/{username}",
            "soundcloud": f"https://soundcloud.com/{username}",
            "twitch": f"https://www.twitch.tv/{username}",
            "github": f"https://github.com/{username}",
            "gitlab": f"https://gitlab.com/{username}",
            "keybase": f"https://keybase.io/{username}",
            "aboutme": f"https://about.me/{username}",
            "gravatar": f"https://gravatar.com/{username}",
            "mastodon": f"https://mastodon.social/@{username}",
            "threads": f"https://www.threads.net/@{username}",
            "substack": f"https://{username}.substack.com",
            "medium": f"https://medium.com/@{username}",
            "devto": f"https://dev.to/{username}",
            "hackernews": f"https://news.ycombinator.com/user?id={username}",
            "producthunt": f"https://www.producthunt.com/@{username}",
            "behance": f"https://www.behance.net/{username}",
            "dribbble": f"https://dribbble.com/{username}",
            "figma": f"https://www.figma.com/@{username}",
            "replit": f"https://replit.com/@{username}",
            "codepen": f"https://codepen.io/{username}",
            "npm": f"https://www.npmjs.com/~{username}",
            "pypi": f"https://pypi.org/user/{username}",
            "docker": f"https://hub.docker.com/u/{username}",
            "kaggle": f"https://www.kaggle.com/{username}",
            "buymeacoffee": f"https://www.buymeacoffee.com/{username}",
            "gumroad": f"https://{username}.gumroad.com",
            "patreon": f"https://www.patreon.com/{username}",
            "fiverr": f"https://www.fiverr.com/{username}",
            "upwork": f"https://www.upwork.com/freelancers/{username}",
            "freelancer": f"https://www.freelancer.com/u/{username}",
        }

        # Check in batches of 10
        site_list = list(extra_sites.items())
        for i in range(0, len(site_list), 10):
            batch = site_list[i:i+10]
            tasks = [self._check_site(client, name, url) for name, url in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)

            await asyncio.sleep(0.5)

        return findings

    async def _check_site(self, client: httpx.AsyncClient, name: str, url: str) -> Finding | None:
        """Check if a username exists on a site."""
        resp = await self._make_request(client, "GET", url, timeout=8, follow_redirects=True)
        if not resp:
            return None

        # 404 = doesn't exist
        if resp.status_code == 404:
            return None

        # 200 = might exist
        if resp.status_code == 200:
            text = resp.text.lower()
            # Check for common "not found" indicators
            not_found_indicators = ["not found", "page not found", "user not found",
                                    "does not exist", "404", "no user", "account suspended"]
            if any(ind in text for ind in not_found_indicators):
                return None

            # Check for positive indicators
            positive_indicators = [name.lower(), "profile", "user", "member", "account"]
            if any(ind in text[:5000] for ind in positive_indicators):
                return Finding(
                    source=f"community:{name}",
                    data_type="profile",
                    value={
                        "platform": name,
                        "username": name,
                        "url": url,
                        "status": "likely_exists",
                    },
                    confidence=0.6,
                    metadata={"site": name, "method": "http_probe"},
                )

        return None

    # ── TgramSearch — 700K+ Telegram channels ───────────────────────

    async def _tgramsearch(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Search TgramSearch for Telegram channels."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            f"https://tgramsearch.com/search?query={username}",
        )
        if resp and resp.status_code == 200:
            text = resp.text
            # Extract channel results
            channels = re.findall(r'href="(https://t\.me/[^"]+)"[^>]*>([^<]+)', text)
            for url, name in channels[:10]:
                findings.append(Finding(
                    source="community:tgramsearch",
                    data_type="search_hit",
                    value={
                        "source": "tgramsearch",
                        "url": url,
                        "name": name.strip(),
                        "query": username,
                    },
                    confidence=0.6,
                    metadata={"site": "tgramsearch"},
                ))

        return findings

    # ── Yandex Dorking (better than Google for some things) ─────────

    async def _yandex_dork(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Yandex search — often finds things Google misses."""
        findings = []

        queries = [
            f'"{username}" site:instagram.com',
            f'"{username}" site:t.me',
            f'"{username}" site:twitter.com OR site:x.com',
        ]

        for query in queries[:2]:
            resp = await self._make_request(
                client, "GET",
                "https://yandex.com/search/",
                params={"text": query, "lr": "84"},  # lr=84 for broader results
            )
            if resp and resp.status_code == 200:
                links = re.findall(r'href="(https?://[^"]*(?:instagram|t\.me|twitter|x\.com)[^"]*)"', resp.text)
                for link in links[:5]:
                    if "yandex" not in link:
                        findings.append(Finding(
                            source="community:yandex",
                            data_type="search_hit",
                            value={"url": link, "query": query[:50]},
                            confidence=0.4,
                            metadata={"type": "yandex_dork"},
                        ))
            await asyncio.sleep(2)

        return findings

    # ── Google Cache — access cached versions ───────────────────────

    async def _google_cache_check(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check Google Cache for cached social media profiles."""
        findings = []

        cache_urls = [
            f"https://webcache.googleusercontent.com/search?q=cache:instagram.com/{username}",
            f"https://webcache.googleusercontent.com/search?q=cache:twitter.com/{username}",
        ]

        for url in cache_urls[:1]:
            resp = await self._make_request(client, "GET", url, timeout=10)
            if resp and resp.status_code == 200 and len(resp.text) > 1000:
                platform = "instagram" if "instagram" in url else "twitter"
                findings.append(Finding(
                    source="community:google_cache",
                    data_type="profile",
                    value={
                        "platform": platform,
                        "username": username,
                        "cached_url": url,
                        "status": "cached_version_available",
                    },
                    confidence=0.5,
                    metadata={"source": "google_cache", "platform": platform},
                ))

        return findings

    # ── Linktree/Beacons — find all connected accounts ──────────────

    async def _linktree_beacons(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check Linktree and Beacons for connected social accounts."""
        findings = []

        for service, base_url in [("linktree", f"https://linktr.ee/{username}"),
                                   ("beacons", f"https://beacons.ai/{username}")]:
            resp = await self._make_request(client, "GET", base_url, timeout=10)
            if resp and resp.status_code == 200:
                text = resp.text
                if "linktr.ee" in resp.url or "beacons.ai" in resp.url:
                    # Extract all links from the page
                    links = re.findall(r'href="(https?://[^"]+)"', text)
                    social_links = []
                    for link in links:
                        if any(s in link for s in ["instagram.com", "twitter.com", "x.com",
                                                     "tiktok.com", "youtube.com", "linkedin.com",
                                                     "github.com", "telegram.me", "t.me",
                                                     "facebook.com", "snapchat.com"]):
                            social_links.append(link)

                    if social_links:
                        findings.append(Finding(
                            source=f"community:{service}",
                            data_type="profile",
                            value={
                                "platform": service,
                                "username": username,
                                "url": base_url,
                                "connected_accounts": list(set(social_links))[:10],
                            },
                            confidence=0.8,
                            metadata={"site": service, "type": "connected_accounts"},
                        ))

        return findings

    # ── Telegram Bots Check ─────────────────────────────────────────

    async def _telegram_bots_check(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check Telegram bots that can reveal info."""
        findings = []

        # These are public Telegram bots that can be checked
        bots_info = {
            "SangMata": {
                "url": f"https://t.me/SangMataInfo_bot",
                "description": "تاریخچه تغییرات نام و یوزرنیم",
                "command": f"Send @{username} to @SangMataInfo_bot",
            },
            "creationdatebot": {
                "url": "https://t.me/creationdatebot",
                "description": "تاریخ ساخت اکانت تلگرام",
                "command": f"Send @{username} to @creationdatebot",
            },
            "username_to_id": {
                "url": "https://t.me/username_to_id_bot",
                "description": "تبدیل یوزرنیم به ID عددی",
                "command": f"Send @{username} to @username_to_id_bot",
            },
            "TgScanRobot": {
                "url": "https://t.me/TgScanRobot",
                "description": "پیدا کردن گروه‌های یک شخص",
                "command": f"Send @{username} to @TgScanRobot",
            },
            "MaigretOsintBot": {
                "url": "https://t.me/MaigretOsintBot",
                "description": "جستجوی یوزرنیم در 1366 سایت",
                "command": f"Send @{username} to @MaigretOsintBot",
            },
        }

        for bot_name, bot_info in bots_info.items():
            findings.append(Finding(
                source=f"community:tg_bot:{bot_name}",
                data_type="search_hit",
                value={
                    "type": "telegram_bot",
                    "bot": bot_name,
                    "url": bot_info["url"],
                    "description": bot_info["description"],
                    "command": bot_info["command"],
                    "username": username,
                },
                confidence=0.7,
                metadata={"type": "telegram_bot_suggestion"},
            ))

        return findings

    # ── OSINT Dorks Collection (community-shared) ───────────────────

    async def _osint_dorks_collection(self, client: httpx.AsyncClient, username: str, target_type: str) -> list[Finding]:
        """Community-shared Google dorks for OSINT."""
        findings = []

        # Community-discovered dork patterns
        dorks = {
            "username": [
                f'"{username}" filetype:pdf',
                f'"{username}" filetype:doc OR filetype:docx',
                f'"{username}" filetype:xlsx',
                f'"{username}" "password" OR "passwd" OR "leak"',
                f'"{username}" site:pastebin.com',
                f'"{username}" site:github.com "password" OR "secret" OR "key"',
                f'"{username}" site:linkedin.com',
                f'"{username}" "phone" OR "mobile" OR "شماره"',
                f'"{username}" "address" OR "آدرس"',
            ],
            "email": [
                f'"{username}" site:pastebin.com',
                f'"{username}" "password" OR "leak" OR "dump"',
                f'"{username}" filetype:sql',
                f'"{username}" site:github.com',
            ],
            "phone": [
                f'"{username}" site:divar.ir',
                f'"{username}" site:sheypoor.com',
                f'"{username}" "آگهی" OR "فروش"',
                f'"{username}" site:instagram.com',
            ],
        }

        target_dorks = dorks.get(target_type, dorks["username"])

        for dork in target_dorks[:4]:
            resp = await self._make_request(
                client, "GET",
                "https://html.duckduckgo.com/html/",
                params={"q": dork},
            )
            if resp and resp.status_code == 200:
                links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', resp.text)
                snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', resp.text, re.DOTALL)

                for i, link in enumerate(links[:3]):
                    if "duckduckgo.com" not in link:
                        actual = re.search(r'uddg=([^&]+)', link)
                        if actual:
                            import urllib.parse
                            link = urllib.parse.unquote(actual.group(1))

                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                        findings.append(Finding(
                            source="community:osint_dork",
                            data_type="search_hit",
                            value={"url": link, "snippet": snippet, "query": dork[:50]},
                            confidence=0.4,
                            metadata={"type": "community_dork"},
                        ))

            await asyncio.sleep(1.5)

        return findings

    # ── Instagram Login Bypass Tips ──────────────────────────────────

    async def _instagram_login_bypass_tips(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Community tips for viewing Instagram without login."""
        findings = []

        # These are documented community techniques
        tips = [
            {
                "trick": "UBlock Origin Filter",
                "description": "نصب اکستنشن UBlock Origin و اضافه کردن فیلتر برای حذف popup لاگین",
                "filter": "##.RnEpo.Yx5HN\n##body:style(overflow: visible !important;)",
                "platform": "instagram",
            },
            {
                "trick": "DevTools Method",
                "description": "F12 → حذف div لاگین → تغییر overflow body به visible",
                "steps": [
                    "1. باز کردن پروفایل اینستاگرام",
                    "2. F12 → Developer Tools",
                    "3. پیدا کردن <div class='RnEpo Yx5HN'> و حذف آن",
                    "4. تغییر <body style='overflow: hidden;'> به overflow: visible",
                ],
                "platform": "instagram",
            },
            {
                "trick": "JSON API",
                "description": "اضافه کردن ?__a=1 به URL پروفایل برای دریافت JSON",
                "url_pattern": f"https://www.instagram.com/{username}/?__a=1",
                "platform": "instagram",
            },
        ]

        for tip in tips:
            findings.append(Finding(
                source="community:ig_tip",
                data_type="search_hit",
                value=tip,
                confidence=0.8,
                metadata={"type": "community_tip", "platform": "instagram"},
            ))

        return findings

    # ── Telegram Export Tips ─────────────────────────────────────────

    async def _telegram_export_tips(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Tips for exporting Telegram data."""
        findings = []

        tips = [
            {
                "trick": "Telegram Desktop Export",
                "description": "خروجی گرفتن از چت/گروه/کانال با Telegram Desktop",
                "steps": [
                    "1. باز کردن Telegram Desktop",
                    "2. باز کردن چت/گروه/کانال مورد نظر",
                    "3. Menu (سه نقطه) → Export Chat History",
                    "4. انتخاب فرمت: HTML یا JSON",
                    "5. فیلتر تاریخ (اختیاری)",
                    "6. Export",
                ],
                "formats": ["HTML", "JSON"],
                "note": "نیازی به عضویت فعال نیست — فقط دسترسی به تاریخچه",
            },
            {
                "trick": "Telegram Search Engines",
                "description": "موتورهای جستجوی مخصوص تلگرام",
                "engines": [
                    {"name": "TgramSearch", "url": "https://tgramsearch.com", "channels": "700K+"},
                    {"name": "Teleteg", "url": "https://teleteg.com", "description": "جستجوی تلگرام"},
                    {"name": "Lyzem", "url": "https://lyzem.com", "description": "موتور جستجوی تلگرام"},
                    {"name": "TelegramDB", "url": "https://telegramdb.org", "description": "دیتابیس کانال/گروه"},
                ],
            },
        ]

        for tip in tips:
            findings.append(Finding(
                source="community:tg_tip",
                data_type="search_hit",
                value=tip,
                confidence=0.85,
                metadata={"type": "community_tip", "platform": "telegram"},
            ))

        return findings
