"""Social media scrapers — Instagram, Twitter/X, TikTok, LinkedIn, Reddit."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class InstagramScraper(BaseModule):
    """Instagram profile and post scraping."""

    name = "instagram"
    category = ModuleCategory.SOCIAL
    description = "Instagram profile analysis — bio, followers, posts, stories"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            # Method 1: Direct profile page
            resp = await self._make_request(
                client, "GET",
                f"https://www.instagram.com/{target}/",
            )
            if resp and resp.status_code == 200:
                text = resp.text

                # Extract embedded JSON data
                import json
                # Try to find shared_data or additional_data
                data_match = re.search(r'window\._sharedData\s*=\s*({.*?});', text)
                if data_match:
                    try:
                        shared = json.loads(data_match.group(1))
                        user = shared.get("entry_data", {}).get("ProfilePage", [{}])[0].get("graphql", {}).get("user", {})
                        if user:
                            findings.append(Finding(
                                source="instagram",
                                data_type="profile",
                                value={
                                    "platform": "instagram",
                                    "username": target,
                                    "url": f"https://www.instagram.com/{target}/",
                                    "full_name": user.get("full_name", ""),
                                    "bio": user.get("biography", ""),
                                    "followers": user.get("edge_followed_by", {}).get("count", 0),
                                    "following": user.get("edge_follow", {}).get("count", 0),
                                    "posts": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                                    "is_private": user.get("is_private", False),
                                    "is_verified": user.get("is_verified", False),
                                    "profile_pic": user.get("profile_pic_url_hd", user.get("profile_pic_url", "")),
                                    "external_url": user.get("external_url", ""),
                                    "is_business": user.get("is_business_account", False),
                                },
                                confidence=0.85,
                                metadata={"site": "instagram", "method": "shared_data"},
                            ))
                    except json.JSONDecodeError:
                        pass

                # Fallback: meta tags
                if not findings:
                    title = re.search(r'<title>([^<]+)</title>', text)
                    desc = re.search(r'<meta[^>]+content="([^"]*)"[^>]*name="description"', text)
                    og_image = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', text)

                    if title and ("Instagram" not in title.group(1) or target.lower() in title.group(1).lower()):
                        findings.append(Finding(
                            source="instagram",
                            data_type="profile",
                            value={
                                "platform": "instagram",
                                "username": target,
                                "url": f"https://www.instagram.com/{target}/",
                                "title": title.group(1).strip() if title else None,
                                "description": desc.group(1).strip()[:300] if desc else None,
                                "profile_pic": og_image.group(1) if og_image else None,
                            },
                            confidence=0.6,
                            metadata={"site": "instagram", "method": "meta_tags"},
                        ))

            # Method 2: i.instagram.com API (public, limited)
            resp2 = await self._make_request(
                client, "GET",
                f"https://i.instagram.com/api/v1/users/web_profile_info/?username={target}",
                headers={"X-IG-App-ID": "936619743392459"},
            )
            if resp2 and resp2.status_code == 200:
                try:
                    data = resp2.json()
                    user = data.get("data", {}).get("user", {})
                    if user:
                        findings.append(Finding(
                            source="instagram:api",
                            data_type="profile",
                            value={
                                "platform": "instagram",
                                "username": target,
                                "full_name": user.get("full_name", ""),
                                "bio": user.get("biography", ""),
                                "followers": user.get("edge_followed_by", {}).get("count", 0),
                                "following": user.get("edge_follow", {}).get("count", 0),
                                "posts": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                                "is_private": user.get("is_private", False),
                                "is_verified": user.get("is_verified", False),
                            },
                            confidence=0.9,
                            metadata={"site": "instagram", "method": "web_api"},
                        ))
                except Exception:
                    pass

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)


class TwitterScraper(BaseModule):
    """Twitter/X profile scraping via web."""

    name = "twitter"
    category = ModuleCategory.SOCIAL
    description = "Twitter/X profile analysis — bio, followers, tweets"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            # Method 1: Nitter instances (public, no auth)
            nitter_instances = [
                "https://nitter.privacydev.net",
                "https://nitter.poast.org",
                "https://nitter.woodland.cafe",
            ]

            for instance in nitter_instances[:2]:
                resp = await self._make_request(client, "GET", f"{instance}/{target}")
                if resp and resp.status_code == 200:
                    text = resp.text
                    if "profile-card" in text or "profile-stat" in text:
                        bio = re.search(r'class="profile-bio"[^>]*>(.*?)</div>', text, re.DOTALL)
                        stats = re.findall(r'class="profile-stat-num"[^>]*>([^<]+)', text)
                        name = re.search(r'class="profile-display-name"[^>]*>([^<]+)', text)

                        findings.append(Finding(
                            source="twitter:nitter",
                            data_type="profile",
                            value={
                                "platform": "twitter",
                                "username": target,
                                "url": f"https://x.com/{target}",
                                "display_name": name.group(1).strip() if name else None,
                                "bio": re.sub(r'<[^>]+>', '', bio.group(1)).strip()[:300] if bio else None,
                                "tweets": stats[0].strip().replace(",", "") if len(stats) > 0 else None,
                                "following": stats[1].strip().replace(",", "") if len(stats) > 1 else None,
                                "followers": stats[2].strip().replace(",", "") if len(stats) > 2 else None,
                            },
                            confidence=0.7,
                            metadata={"site": "twitter", "method": "nitter", "instance": instance},
                        ))
                        break

            # Method 2: Syndication API (public, limited)
            resp = await self._make_request(
                client, "GET",
                f"https://syndication.twitter.com/srv/timeline-profile/screen-name/{target}",
            )
            if resp and resp.status_code == 200:
                text = resp.text
                if "timeline" in text.lower():
                    tweets = re.findall(r'data-tweet-id="(\d+)"', text)
                    findings.append(Finding(
                        source="twitter:syndication",
                        data_type="profile",
                        value={
                            "platform": "twitter",
                            "username": target,
                            "url": f"https://x.com/{target}",
                            "recent_tweet_ids": tweets[:10],
                            "tweets_found": len(tweets),
                        },
                        confidence=0.6,
                        metadata={"site": "twitter", "method": "syndication"},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)


class TikTokScraper(BaseModule):
    """TikTok profile scraping."""

    name = "tiktok"
    category = ModuleCategory.SOCIAL
    description = "TikTok profile analysis"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            resp = await self._make_request(
                client, "GET",
                f"https://www.tiktok.com/@{target}",
            )
            if resp and resp.status_code == 200:
                text = resp.text

                # Extract SIGI_STATE or __UNIVERSAL_DATA_FOR_REHYDRATION__
                import json
                data_match = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', text)
                if data_match:
                    try:
                        data = json.loads(data_match.group(1))
                        user = data.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {}).get("userInfo", {}).get("user", {})
                        stats = data.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {}).get("userInfo", {}).get("stats", {})

                        if user:
                            findings.append(Finding(
                                source="tiktok",
                                data_type="profile",
                                value={
                                    "platform": "tiktok",
                                    "username": target,
                                    "url": f"https://www.tiktok.com/@{target}",
                                    "nickname": user.get("nickname", ""),
                                    "bio": user.get("signature", ""),
                                    "followers": stats.get("followerCount", 0),
                                    "following": stats.get("followingCount", 0),
                                    "likes": stats.get("heartCount", 0),
                                    "videos": stats.get("videoCount", 0),
                                    "verified": user.get("verified", False),
                                    "private": user.get("privateAccount", False),
                                },
                                confidence=0.85,
                                metadata={"site": "tiktok", "method": "universal_data"},
                            ))
                    except json.JSONDecodeError:
                        pass

                # Fallback: meta tags
                if not findings:
                    desc = re.search(r'<meta[^>]+content="([^"]*)"[^>]*name="description"', text)
                    if desc:
                        findings.append(Finding(
                            source="tiktok",
                            data_type="profile",
                            value={
                                "platform": "tiktok",
                                "username": target,
                                "url": f"https://www.tiktok.com/@{target}",
                                "description": desc.group(1).strip()[:300],
                            },
                            confidence=0.5,
                            metadata={"site": "tiktok", "method": "meta_tags"},
                        ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)


class RedditScraper(BaseModule):
    """Reddit profile and post scraping + Pullpush for deleted content."""

    name = "reddit"
    category = ModuleCategory.SOCIAL
    description = "Reddit profile analysis + deleted content via Pullpush"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("/u/", "").replace("u/", "").strip()

        async with self.create_client() as client:
            # Reddit public JSON API
            resp = await self._make_request(
                client, "GET",
                f"https://www.reddit.com/user/{target}/about.json",
                headers={"User-Agent": "social-recon/2.0"},
            )
            if resp and resp.status_code == 200:
                data = resp.json().get("data", {})
                if data:
                    findings.append(Finding(
                        source="reddit",
                        data_type="profile",
                        value={
                            "platform": "reddit",
                            "username": target,
                            "url": f"https://www.reddit.com/user/{target}",
                            "link_karma": data.get("link_karma", 0),
                            "comment_karma": data.get("comment_karma", 0),
                            "total_karma": data.get("total_karma", 0),
                            "created_utc": data.get("created_utc", 0),
                            "is_gold": data.get("is_gold", False),
                            "is_mod": data.get("is_mod", False),
                            "verified": data.get("verified", False),
                            "has_verified_email": data.get("has_verified_email", False),
                        },
                        confidence=0.9,
                        metadata={"site": "reddit", "method": "public_api"},
                    ))

            # Pullpush.io for deleted content
            resp = await self._make_request(
                client, "GET",
                "https://api.pullpush.io/reddit/search/submission/",
                params={"author": target, "size": 20, "sort": "desc", "sort_type": "created_utc"},
            )
            if resp and resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    findings.append(Finding(
                        source="reddit:pullpush",
                        data_type="profile",
                        value={
                            "platform": "reddit",
                            "username": target,
                            "archived_posts": len(data),
                            "recent_posts": [
                                {"title": p.get("title", "")[:100], "subreddit": p.get("subreddit", ""), "score": p.get("score", 0)}
                                for p in data[:10]
                            ],
                        },
                        confidence=0.85,
                        metadata={"site": "reddit", "method": "pullpush", "type": "deleted_content"},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)
