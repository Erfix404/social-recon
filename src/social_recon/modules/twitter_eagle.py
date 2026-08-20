"""Twitter/X Eagle Eye — comprehensive Twitter OSINT module.

Free techniques (no API key):
1. Syndication API — public tweet lookup by ID (no auth)
2. oEmbed API — tweet embed data (no auth)
3. Google Dorking — find tweets, profiles, media
4. Wayback Machine — deleted tweet recovery
5. Nitter instances — anonymous profile viewing
6. Advanced search operators via DuckDuckGo

Enhanced techniques (optional, with cookies):
7. twscrape — full tweet/search/follower extraction
8. twikit — Twitter internal API

Requires: TWITTER_AUTH_TOKEN + TWITTER_CT0 for enhanced features.
Without them, uses only free public methods (still powerful).
"""
import asyncio
import json
import re
import time
import random

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class TwitterEagleEye(BaseModule):
    """Eagle-eye Twitter/X OSINT — free public methods + optional scraping."""

    name = "twitter_eagle"
    category = ModuleCategory.SOCIAL
    description = "Deep Twitter/X recon: syndication API, Google dorks, archives, scraping"
    supported_input_types = ["username", "email"]

    def __init__(self, config=None):
        super().__init__(config)
        import os
        self.auth_token = os.environ.get("TWITTER_AUTH_TOKEN", "")
        self.ct0 = os.environ.get("TWITTER_CT0", "")
        self.has_cookies = bool(self.auth_token and self.ct0)

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            tasks = [
                self._nitter_scrape(client, target),
                self._syndication_lookup(client, target),
                self._google_dork_tweets(client, target),
                self._google_dork_profile(client, target),
                self._wayback_tweets(client, target),
                self._oembed_profile(client, target),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Finding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    errors.append(str(result)[:200])

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.source}:{f.data_type}:{str(f.value)[:60]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=unique,
            errors=errors,
        )

    # ── Nitter Instances (Free, No Auth) ────────────────────────────

    async def _nitter_scrape(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Scrape Nitter instances for profile and tweets."""
        findings = []

        nitter_instances = [
            "https://nitter.privacydev.net",
            "https://nitter.poast.org",
            "https://nitter.woodland.cafe",
            "https://nitter.net",
            "https://nitter.cz",
        ]

        for instance in nitter_instances[:3]:
            resp = await self._make_request(client, "GET", f"{instance}/{username}", timeout=10)
            if not resp or resp.status_code != 200:
                continue

            text = resp.text
            if "profile-card" not in text and "timeline" not in text:
                continue

            # Extract profile info
            bio = re.search(r'class="profile-bio"[^>]*>(.*?)</div>', text, re.DOTALL)
            stats = re.findall(r'class="profile-stat-num"[^>]*>([^<]+)', text)
            name = re.search(r'class="profile-display-name"[^>]*>([^<]+)', text)
            avatar = re.search(r'class="profile-avatar"[^>]*src="([^"]+)"', text)
            banner = re.search(r'class="profile-banner"[^>]*src="([^"]+)"', text)
            location = re.search(r'class="profile-location"[^>]*>([^<]+)', text)
            website = re.search(r'class="profile-website"[^>]*href="([^"]+)"', text)
            join_date = re.search(r'class="profile-joindate"[^>]*>([^<]+)', text)

            profile = {
                "platform": "twitter",
                "username": username,
                "url": f"https://x.com/{username}",
                "display_name": name.group(1).strip() if name else None,
                "bio": re.sub(r'<[^>]+>', '', bio.group(1)).strip()[:300] if bio else None,
                "tweets": stats[0].strip().replace(",", "") if len(stats) > 0 else None,
                "following": stats[1].strip().replace(",", "") if len(stats) > 1 else None,
                "followers": stats[2].strip().replace(",", "") if len(stats) > 2 else None,
                "likes": stats[3].strip().replace(",", "") if len(stats) > 3 else None,
                "location": location.group(1).strip() if location else None,
                "website": website.group(1).strip() if website else None,
                "join_date": join_date.group(1).strip() if join_date else None,
                "avatar": avatar.group(1) if avatar else None,
                "banner": banner.group(1) if banner else None,
                "source": instance,
            }

            findings.append(Finding(
                source=f"twitter:nitter:{instance.split('//')[1]}",
                data_type="profile",
                value=profile,
                confidence=0.75,
                metadata={"site": "twitter", "method": "nitter"},
            ))

            # Extract tweets from timeline
            tweet_blocks = re.findall(
                r'class="timeline-item"[^>]*>(.*?)(?=class="timeline-item"|$)',
                text, re.DOTALL,
            )

            for i, tweet_html in enumerate(tweet_blocks[:10]):
                tweet_text = re.search(r'class="tweet-content[^"]*"[^>]*>(.*?)</div>', tweet_html, re.DOTALL)
                tweet_link = re.search(r'class="tweet-link"[^>]*href="([^"]+)"', tweet_html)
                tweet_date = re.search(r'class="tweet-date"[^>]*title="([^"]+)"', tweet_html)
                tweet_stats = re.findall(r'class="tweet-stat-count"[^>]*>([^<]+)', tweet_html)

                if tweet_text:
                    findings.append(Finding(
                        source=f"twitter:nitter:{instance.split('//')[1]}",
                        data_type="profile",
                        value={
                            "type": "tweet",
                            "platform": "twitter",
                            "username": username,
                            "text": re.sub(r'<[^>]+>', '', tweet_text.group(1)).strip()[:300],
                            "url": f"https://x.com{tweet_link.group(1)}" if tweet_link else "",
                            "date": tweet_date.group(1) if tweet_date else "",
                            "replies": tweet_stats[0].strip() if len(tweet_stats) > 0 else "0",
                            "retweets": tweet_stats[1].strip() if len(tweet_stats) > 1 else "0",
                            "likes": tweet_stats[2].strip() if len(tweet_stats) > 2 else "0",
                        },
                        confidence=0.7,
                        metadata={"site": "twitter", "type": "tweet"},
                    ))

            break  # Success — don't try other instances

        return findings

    # ── Syndication API (Free, No Auth) ─────────────────────────────

    async def _syndication_lookup(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Use Twitter Syndication API for tweet data (public, no auth)."""
        findings = []

        # First, try to find recent tweet IDs via Google
        resp = await self._make_request(
            client, "GET",
            "https://html.duckduckgo.com/html/",
            params={"q": f'site:x.com/{username}/status/'},
        )
        if resp and resp.status_code == 200:
            tweet_ids = re.findall(r'(?:twitter|x)\.com/' + re.escape(username) + r'/status/(\d+)', resp.text)
            tweet_ids = list(dict.fromkeys(tweet_ids))[:5]  # Deduplicate, limit to 5

            for tweet_id in tweet_ids:
                # Syndication API — public, no auth needed
                syn_resp = await self._make_request(
                    client, "GET",
                    f"https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&lang=en",
                )
                if syn_resp and syn_resp.status_code == 200:
                    try:
                        data = syn_resp.json()
                        findings.append(Finding(
                            source="twitter:syndication",
                            data_type="profile",
                            value={
                                "type": "tweet",
                                "platform": "twitter",
                                "tweet_id": tweet_id,
                                "text": data.get("text", "")[:300],
                                "username": data.get("user", {}).get("screen_name", username),
                                "name": data.get("user", {}).get("name", ""),
                                "likes": data.get("favorite_count", 0),
                                "retweets": data.get("conversation_count", 0),
                                "created_at": data.get("created_at", ""),
                                "lang": data.get("lang", ""),
                                "url": f"https://x.com/{username}/status/{tweet_id}",
                            },
                            confidence=0.85,
                            metadata={"site": "twitter", "method": "syndication_api"},
                        ))
                    except json.JSONDecodeError:
                        pass

                await asyncio.sleep(0.5)

        return findings

    # ── oEmbed API (Free, No Auth) ──────────────────────────────────

    async def _oembed_profile(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Use Twitter oEmbed API for embed data."""
        findings = []

        # oEmbed for profile URL
        resp = await self._make_request(
            client, "GET",
            "https://publish.twitter.com/oembed",
            params={"url": f"https://x.com/{username}"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                findings.append(Finding(
                    source="twitter:oembed",
                    data_type="profile",
                    value={
                        "platform": "twitter",
                        "username": username,
                        "author_name": data.get("author_name", ""),
                        "author_url": data.get("author_url", ""),
                        "html": data.get("html", "")[:200],
                    },
                    confidence=0.7,
                    metadata={"site": "twitter", "method": "oembed"},
                ))
            except Exception:
                pass

        return findings

    # ── Google Dorking (Free, No Auth) ──────────────────────────────

    async def _google_dork_tweets(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Find tweets via Google Dorking."""
        findings = []

        dorks = [
            f'site:x.com/{username}/status/',
            f'site:twitter.com "{username}" tweet',
            f'"{username}" site:x.com -site:twitter.com',
            f'site:x.com "{username}" "replied to"',
        ]

        for dork in dorks[:3]:
            resp = await self._make_request(
                client, "GET",
                "https://html.duckduckgo.com/html/",
                params={"q": dork},
            )
            if resp and resp.status_code == 200:
                links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', resp.text)
                snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', resp.text, re.DOTALL)

                for i, link in enumerate(links[:5]):
                    if "duckduckgo.com" in link:
                        continue
                    # Extract actual URL
                    actual = re.search(r'uddg=([^&]+)', link)
                    if actual:
                        import urllib.parse
                        link = urllib.parse.unquote(actual.group(1))

                    if ("x.com" in link or "twitter.com" in link):
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                        findings.append(Finding(
                            source="twitter:google_dork",
                            data_type="search_hit",
                            value={"url": link, "snippet": snippet, "query": dork[:50]},
                            confidence=0.5,
                            metadata={"type": "twitter_dork"},
                        ))

            await asyncio.sleep(random.uniform(1.5, 3.0))

        return findings

    async def _google_dork_profile(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Find Twitter profile info via Google."""
        findings = []

        dorks = [
            f'site:x.com "{username}"',
            f'"{username}" twitter profile bio',
            f'"{username}" site:twitter.com',
        ]

        for dork in dorks[:2]:
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
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                        findings.append(Finding(
                            source="twitter:google_profile",
                            data_type="search_hit",
                            value={"url": link, "snippet": snippet},
                            confidence=0.4,
                            metadata={"type": "twitter_profile_dork"},
                        ))
            await asyncio.sleep(1.5)

        return findings

    # ── Wayback Machine (Free, No Auth) ─────────────────────────────

    async def _wayback_tweets(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check Wayback Machine for archived tweets."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"x.com/{username}/status/*",
                "output": "json",
                "fl": "timestamp,original,statuscode",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": 20,
            },
            timeout=20,
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if len(data) > 1:
                    headers = data[0]
                    for row in data[1:50]:
                        entry = dict(zip(headers, row))
                        tweet_url = entry.get("original", "")
                        timestamp = entry.get("timestamp", "")

                        # Extract tweet ID from URL
                        tweet_id = re.search(r'/status/(\d+)', tweet_url)

                        findings.append(Finding(
                            source="twitter:wayback",
                            data_type="profile",
                            value={
                                "type": "archived_tweet",
                                "platform": "twitter",
                                "username": username,
                                "url": tweet_url,
                                "tweet_id": tweet_id.group(1) if tweet_id else "",
                                "archive_url": f"https://web.archive.org/web/{timestamp}/{tweet_url}",
                                "timestamp": timestamp,
                            },
                            confidence=0.8,
                            metadata={"site": "twitter", "method": "wayback"},
                        ))

                    findings.append(Finding(
                        source="twitter:wayback",
                        data_type="domain_info",
                        value={
                            "username": username,
                            "total_archived": len(data) - 1,
                            "type": "wayback_summary",
                        },
                        confidence=0.85,
                        metadata={"source": "wayback", "type": "summary"},
                    ))
            except Exception:
                pass

        return findings
