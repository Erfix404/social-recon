"""Instagram Eagle Eye — comprehensive Instagram OSINT module.

Techniques:
1. Internal API (i.instagram.com) — profile, posts, followers, following
2. Google Dorking — commented posts, tagged photos, activity
3. Web viewers (Picuki, Dumpor, Imginn) — anonymous profile viewing
4. Meta tags extraction — basic profile from public page
5. Business info extraction — email, phone, category
6. Story/Highlight detection
7. Tagged posts discovery
8. Comment activity on OTHER people's posts
9. Connected account detection

Requires: INSTAGRAM_SESSION_ID env var for authenticated features (optional).
Without it, uses public endpoints + Google dorking (still powerful).
"""
import asyncio
import json
import re
import time
import random

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


INSTAGRAM_APP_ID = "936619743392459"

# Mobile API headers — more effective than web headers
MOBILE_HEADERS = {
    "User-Agent": "Instagram 275.0.0.27.98 Android (30/11; 420dpi; 1080x2400; samsung; SM-G991B; o1s; exynos2100; en_US; 314665258)",
    "X-IG-App-ID": INSTAGRAM_APP_ID,
    "X-IG-Capabilities": "3brTvx0=",
    "X-IG-Connection-Type": "WIFI",
    "Accept-Language": "en-US",
    "Accept-Encoding": "gzip, deflate",
}


class InstagramEagleEye(BaseModule):
    """Eagle-eye Instagram OSINT — profile, followers, posts, comments, activity."""

    name = "instagram_eagle"
    category = ModuleCategory.SOCIAL
    description = "Deep Instagram recon: profile, followers, posts, comments, activity, tagged"
    supported_input_types = ["username", "email"]

    def __init__(self, config=None):
        super().__init__(config)
        import os
        self.session_id = os.environ.get("INSTAGRAM_SESSION_ID", "")
        self.has_auth = bool(self.session_id)

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as client:
            # Run all techniques concurrently
            tasks = [
                self._public_api_profile(client, target),
                self._meta_tags_profile(client, target),
                self._google_dork_comments(client, target),
                self._google_dork_tagged(client, target),
                self._google_dork_general(client, target),
                self._web_viewer_scrape(client, target, "picuki"),
                self._web_viewer_scrape(client, target, "imginn"),
            ]

            # Authenticated techniques
            if self.has_auth:
                tasks.extend([
                    self._auth_api_profile(client, target),
                    self._auth_api_posts(client, target),
                    self._auth_api_followers(client, target),
                    self._auth_api_following(client, target),
                    self._auth_api_stories(client, target),
                    self._auth_api_tagged(client, target),
                ])

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

    # ── Public API (no auth) ────────────────────────────────────────

    async def _public_api_profile(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get profile via Instagram's public and mobile APIs."""
        findings = []

        # Method 1: web_profile_info endpoint (web)
        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers={"X-IG-App-ID": INSTAGRAM_APP_ID, "X-Requested-With": "XMLHttpRequest"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                user = data.get("data", {}).get("user", {})
                if user:
                    findings.extend(self._parse_user_data(user, "public_api"))
            except Exception:
                pass

        # Method 2: Mobile API — usernameinfo endpoint (more data, mobile headers)
        resp2 = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/{username}/usernameinfo/",
            headers=MOBILE_HEADERS,
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                user = data.get("user", {})
                if user:
                    findings.extend(self._parse_mobile_user_data(user, "mobile_api"))
            except Exception:
                pass

        # Method 3: ?__a=1 endpoint
        resp3 = await self._make_request(
            client, "GET",
            f"https://www.instagram.com/{username}/?__a=1&__d=dis",
            headers={"X-IG-App-ID": INSTAGRAM_APP_ID},
        )
        if resp3 and resp3.status_code == 200:
            try:
                data = resp3.json()
                user = data.get("graphql", {}).get("user", {})
                if user and not findings:
                    findings.extend(self._parse_user_data(user, "web_a1"))
            except Exception:
                pass

        return findings

    def _parse_mobile_user_data(self, user: dict, method: str) -> list[Finding]:
        """Parse mobile API user data — has extra fields like HD pic, address."""
        findings = []
        username = user.get("username", "")

        profile = {
            "platform": "instagram",
            "username": username,
            "url": f"https://www.instagram.com/{username}/",
            "user_id": user.get("pk", ""),
            "full_name": user.get("full_name", ""),
            "bio": user.get("biography", ""),
            "followers": user.get("follower_count", 0),
            "following": user.get("following_count", 0),
            "posts_count": user.get("media_count", 0),
            "is_private": user.get("is_private", False),
            "is_verified": user.get("is_verified", False),
            "is_business": user.get("is_business", False),
            "business_category": user.get("business_category_name", ""),
            "public_email": user.get("public_email", ""),
            "public_phone": user.get("public_phone_number", ""),
            "contact_phone": user.get("contact_phone_number", ""),
            "external_url": user.get("external_url", ""),
            "profile_pic": user.get("profile_pic_url", ""),
            "hd_profile_pic": (user.get("hd_profile_pic_url_info", {}) or {}).get("url", ""),
            "address_street": user.get("address_street", ""),
            "city_name": user.get("city_name", ""),
            "latitude": user.get("latitude"),
            "longitude": user.get("longitude"),
        }

        # Bio hashtags and mentions
        import re
        profile["bio_hashtags"] = re.findall(r'#(\w+)', user.get("biography", ""))
        profile["bio_mentions"] = re.findall(r'@(\w+)', user.get("biography", ""))

        findings.append(Finding(
            source=f"instagram:{method}",
            data_type="profile",
            value=profile,
            confidence=0.92,
            metadata={"site": "instagram", "method": method},
        ))

        return findings

    def _parse_user_data(self, user: dict, method: str) -> list[Finding]:
        """Parse Instagram user data into findings."""
        findings = []
        username = user.get("username", "")

        # Main profile
        profile = {
            "platform": "instagram",
            "username": username,
            "url": f"https://www.instagram.com/{username}/",
            "full_name": user.get("full_name", ""),
            "bio": user.get("biography", ""),
            "bio_links": [l.get("url") for l in user.get("bio_links", []) if l.get("url")],
            "followers": user.get("edge_followed_by", {}).get("count", 0),
            "following": user.get("edge_follow", {}).get("count", 0),
            "posts_count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
            "is_private": user.get("is_private", False),
            "is_verified": user.get("is_verified", False),
            "is_business": user.get("is_business_account", False),
            "business_category": user.get("business_category_name", ""),
            "profile_pic_hd": user.get("profile_pic_url_hd", user.get("profile_pic_url", "")),
            "external_url": user.get("external_url", ""),
            "fb_id": user.get("fbid", ""),
            "user_id": user.get("id", ""),
        }

        # Business contact info
        if user.get("is_business_account") or user.get("is_professional_account"):
            profile["business_email"] = user.get("business_email", "")
            profile["business_phone"] = user.get("business_phone_number", "")
            profile["business_address"] = user.get("business_address_json", "")

        findings.append(Finding(
            source=f"instagram:{method}",
            data_type="profile",
            value=profile,
            confidence=0.9,
            metadata={"site": "instagram", "method": method},
        ))

        # Extract recent posts
        edges = user.get("edge_owner_to_timeline_media", {}).get("edges", [])
        for edge in edges[:12]:
            node = edge.get("node", {})
            post = {
                "type": "post",
                "shortcode": node.get("shortcode", ""),
                "url": f"https://www.instagram.com/p/{node.get('shortcode', '')}/",
                "caption": "",
                "likes": node.get("edge_liked_by", {}).get("count", 0) or node.get("edge_media_preview_like", {}).get("count", 0),
                "comments": node.get("edge_media_to_comment", {}).get("count", 0),
                "timestamp": node.get("taken_at_timestamp", 0),
                "is_video": node.get("is_video", False),
                "views": node.get("video_view_count", 0),
                "location": node.get("location", {}).get("name", "") if node.get("location") else "",
            }

            # Caption
            caption_edges = node.get("edge_media_to_caption", {}).get("edges", [])
            if caption_edges:
                post["caption"] = caption_edges[0].get("node", {}).get("text", "")[:300]

            # Image URL
            display_url = node.get("display_url", "")
            if display_url:
                post["image_url"] = display_url

            findings.append(Finding(
                source=f"instagram:{method}",
                data_type="profile",
                value={"type": "post", "platform": "instagram", "username": username, **post},
                confidence=0.9,
                metadata={"site": "instagram", "type": "post"},
            ))

        # Extract tagged count
        tagged_count = user.get("edge_user_to_photos_of_you", {}).get("count", 0)
        if tagged_count:
            findings.append(Finding(
                source=f"instagram:{method}",
                data_type="profile",
                value={
                    "type": "tagged_count",
                    "platform": "instagram",
                    "username": username,
                    "tagged_count": tagged_count,
                },
                confidence=0.9,
                metadata={"site": "instagram", "type": "tagged_count"},
            ))

        # Highlight count
        highlight_count = user.get("highlight_reel_count", 0)
        if highlight_count:
            findings.append(Finding(
                source=f"instagram:{method}",
                data_type="profile",
                value={
                    "type": "highlights",
                    "platform": "instagram",
                    "username": username,
                    "highlight_count": highlight_count,
                },
                confidence=0.85,
                metadata={"site": "instagram", "type": "highlights"},
            ))

        return findings

    # ── Google Dorking for Instagram Activity ───────────────────────

    async def _google_dork_comments(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Find posts where the user commented via Google dorking.

        This is the trick: site:instagram.com/p/ "username" shows posts
        where the user left comments.
        """
        findings = []

        dorks = [
            f'site:instagram.com/p/ "{username}"',
            f'site:instagram.com "{username}" comment',
            f'site:instagram.com "{username}" inurl:/p/',
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

                for i, link in enumerate(links[:10]):
                    if "duckduckgo.com" in link:
                        continue
                    # Extract actual URL from DDG redirect
                    actual = re.search(r'uddg=([^&]+)', link)
                    if actual:
                        import urllib.parse
                        link = urllib.parse.unquote(actual.group(1))

                    if "instagram.com/p/" in link or "instagram.com/reel/" in link:
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                        # Extract shortcode from URL
                        shortcode = re.search(r'instagram\.com/(?:p|reel)/([A-Za-z0-9_-]+)', link)

                        findings.append(Finding(
                            source="instagram:google_dork_comments",
                            data_type="profile",
                            value={
                                "type": "commented_post",
                                "platform": "instagram",
                                "username": username,
                                "post_url": link,
                                "shortcode": shortcode.group(1) if shortcode else "",
                                "snippet": snippet,
                            },
                            confidence=0.6,
                            metadata={"site": "instagram", "type": "comment_activity"},
                        ))

            await asyncio.sleep(random.uniform(1.5, 3.0))

        return findings

    async def _google_dork_tagged(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Find tagged photos via Google dorking."""
        findings = []

        dork = f'site:instagram.com "{username}" tagged OR "photo by"'
        resp = await self._make_request(
            client, "GET",
            "https://html.duckduckgo.com/html/",
            params={"q": dork},
        )
        if resp and resp.status_code == 200:
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', resp.text)
            for link in links[:5]:
                if "duckduckgo.com" not in link and "instagram.com" in link:
                    actual = re.search(r'uddg=([^&]+)', link)
                    if actual:
                        import urllib.parse
                        link = urllib.parse.unquote(actual.group(1))
                    findings.append(Finding(
                        source="instagram:google_dork_tagged",
                        data_type="profile",
                        value={"type": "tagged_photo", "platform": "instagram", "username": username, "url": link},
                        confidence=0.5,
                        metadata={"site": "instagram", "type": "tagged"},
                    ))

        return findings

    async def _google_dork_general(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """General Google dorking for Instagram profile."""
        findings = []

        dorks = [
            f'site:instagram.com "{username}"',
            f'"{username}" instagram profile',
            f'"{username}" instagram bio',
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

                for i, link in enumerate(links[:5]):
                    if "duckduckgo.com" not in link:
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:200]
                        findings.append(Finding(
                            source="instagram:google_dork",
                            data_type="search_hit",
                            value={"url": link, "snippet": snippet, "query": dork[:50]},
                            confidence=0.4,
                            metadata={"type": "instagram_dork"},
                        ))
            await asyncio.sleep(1.5)

        return findings

    # ── Web Viewers (anonymous) ─────────────────────────────────────

    async def _web_viewer_scrape(self, client: httpx.AsyncClient, username: str, viewer: str) -> list[Finding]:
        """Scrape Instagram data from anonymous web viewers."""
        findings = []

        viewer_urls = {
            "picuki": f"https://picuki.com/profile/{username}",
            "imginn": f"https://imginn.com/{username}",
            "dumpor": f"https://dumpor.com/v/{username}",
            "gramhir": f"https://gramhir.com/profile/{username}/{username}",
            "storiesig": f"https://storiesig.net/stories/{username}",
            "instastories": f"https://insta-stories.online/en/profile/{username}",
            "inflact": f"https://inflact.com/profiles/{username}/",
        }

        url = viewer_urls.get(viewer)
        if not url:
            return findings

        resp = await self._make_request(client, "GET", url, timeout=15)
        if not resp or resp.status_code != 200:
            return findings

        text = resp.text

        # Extract profile info from viewer page
        followers = re.search(r'([\d,.]+[KkMm]?)\s*(?:follower|فالوور)', text)
        following = re.search(r'([\d,.]+[KkMm]?)\s*(?:following|فالویینگ)', text)
        posts = re.search(r'([\d,.]+[KkMm]?)\s*(?:post|پست)', text)
        bio = re.search(r'class="[^"]*bio[^"]*"[^>]*>(.*?)</(?:div|p)>', text, re.DOTALL)
        name = re.search(r'class="[^"]*name[^"]*"[^>]*>([^<]+)', text)

        # Extract post links
        post_links = re.findall(r'href="(/p/[A-Za-z0-9_-]+)"', text)
        post_links += re.findall(r'href="(/reel/[A-Za-z0-9_-]+)"', text)

        if followers or posts or post_links:
            findings.append(Finding(
                source=f"instagram:{viewer}",
                data_type="profile",
                value={
                    "platform": "instagram",
                    "source": viewer,
                    "username": username,
                    "url": url,
                    "followers": followers.group(1) if followers else None,
                    "following": following.group(1) if following else None,
                    "posts": posts.group(1) if posts else None,
                    "bio": re.sub(r'<[^>]+>', '', bio.group(1)).strip()[:300] if bio else None,
                    "display_name": name.group(1).strip() if name else None,
                    "post_links_found": len(set(post_links)),
                },
                confidence=0.7,
                metadata={"site": "instagram", "method": f"viewer:{viewer}"},
            ))

            # Extract individual posts from viewer
            for link in list(set(post_links))[:6]:
                shortcode = link.split("/")[-1] if link else ""
                findings.append(Finding(
                    source=f"instagram:{viewer}",
                    data_type="profile",
                    value={
                        "type": "viewer_post",
                        "platform": "instagram",
                        "username": username,
                        "shortcode": shortcode,
                        "viewer_url": f"https://{viewer}.com{link}",
                    },
                    confidence=0.65,
                    metadata={"site": "instagram", "type": "viewer_post", "viewer": viewer},
                ))

        return findings

    # ── Meta Tags (fallback) ────────────────────────────────────────

    async def _meta_tags_profile(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Extract profile from meta tags (fallback method)."""
        findings = []

        resp = await self._make_request(client, "GET", f"https://www.instagram.com/{username}/")
        if not resp or resp.status_code != 200:
            return findings

        text = resp.text

        title = re.search(r'<title>([^<]+)</title>', text)
        desc = re.search(r'<meta[^>]+content="([^"]*)"[^>]*name="description"', text)
        og_desc = re.search(r'<meta[^>]+property="og:description"[^>]+content="([^"]+)"', text)
        og_image = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', text)

        if title and username.lower() in title.group(1).lower():
            # Parse follower/post counts from description
            # Format: "X Followers, Y Following, Z Posts"
            desc_text = og_desc.group(1) if og_desc else (desc.group(1) if desc else "")
            followers_m = re.search(r'([\d,.]+[KkMm]?)\s*[Ff]ollower', desc_text)
            following_m = re.search(r'([\d,.]+[KkMm]?)\s*[Ff]ollowing', desc_text)
            posts_m = re.search(r'([\d,.]+[KkMm]?)\s*[Pp]ost', desc_text)

            findings.append(Finding(
                source="instagram:meta_tags",
                data_type="profile",
                value={
                    "platform": "instagram",
                    "username": username,
                    "url": f"https://www.instagram.com/{username}/",
                    "title": title.group(1).strip(),
                    "description": desc_text[:300],
                    "followers": followers_m.group(1) if followers_m else None,
                    "following": following_m.group(1) if following_m else None,
                    "posts": posts_m.group(1) if posts_m else None,
                    "profile_pic": og_image.group(1) if og_image else None,
                },
                confidence=0.6,
                metadata={"site": "instagram", "method": "meta_tags"},
            ))

        return findings

    # ── Authenticated API (requires INSTAGRAM_SESSION_ID) ───────────

    async def _auth_api_profile(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Full profile via authenticated API."""
        findings = []
        headers = self._auth_headers()

        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                user = data.get("data", {}).get("user", {})
                if user:
                    # Auth gives us more data
                    profile = {
                        "platform": "instagram",
                        "username": username,
                        "user_id": user.get("id", ""),
                        "full_name": user.get("full_name", ""),
                        "bio": user.get("biography", ""),
                        "followers": user.get("edge_followed_by", {}).get("count", 0),
                        "following": user.get("edge_follow", {}).get("count", 0),
                        "posts_count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                        "is_private": user.get("is_private", False),
                        "is_verified": user.get("is_verified", False),
                        "is_business": user.get("is_business_account", False),
                        "business_category": user.get("business_category_name", ""),
                        "business_email": user.get("business_email", ""),
                        "business_phone": user.get("business_phone_number", ""),
                        "external_url": user.get("external_url", ""),
                        "profile_pic_hd": user.get("profile_pic_url_hd", ""),
                        "hd_profile_pic": user.get("hd_profile_pic_url_info", {}).get("url", ""),
                        "fb_page": user.get("connected_fb_page", ""),
                    }
                    findings.append(Finding(
                        source="instagram:auth_api",
                        data_type="profile",
                        value=profile,
                        confidence=0.95,
                        metadata={"site": "instagram", "method": "auth_api"},
                    ))
            except Exception:
                pass

        return findings

    async def _auth_api_posts(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get detailed posts via authenticated API."""
        findings = []
        headers = self._auth_headers()

        # First get user ID
        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
        )
        if not resp or resp.status_code != 200:
            return findings

        try:
            user_id = resp.json().get("data", {}).get("user", {}).get("id", "")
            if not user_id:
                return findings
        except Exception:
            return findings

        # Get feed
        resp2 = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/feed/user/{user_id}/",
            headers=headers,
            params={"count": 24},
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                for item in data.get("items", [])[:24]:
                    caption = item.get("caption", {})
                    findings.append(Finding(
                        source="instagram:auth_feed",
                        data_type="profile",
                        value={
                            "type": "post_detail",
                            "platform": "instagram",
                            "username": username,
                            "id": item.get("id", ""),
                            "shortcode": item.get("code", ""),
                            "url": f"https://www.instagram.com/p/{item.get('code', '')}/",
                            "caption": (caption.get("text", "") if caption else "")[:300],
                            "likes": item.get("like_count", 0),
                            "comments": item.get("comment_count", 0),
                            "timestamp": item.get("taken_at", 0),
                            "is_video": item.get("media_type", 0) == 2,
                            "views": item.get("view_count", 0),
                            "location": item.get("location", {}).get("name", "") if item.get("location") else "",
                            "usertags": [t.get("user", {}).get("username", "") for t in item.get("usertags", {}).get("in", [])],
                        },
                        confidence=0.95,
                        metadata={"site": "instagram", "type": "post_detail"},
                    ))
            except Exception:
                pass

        return findings

    async def _auth_api_followers(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get followers list via authenticated API."""
        return await self._auth_api_user_list(client, username, "followers")

    async def _auth_api_following(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get following list via authenticated API."""
        return await self._auth_api_user_list(client, username, "following")

    async def _auth_api_user_list(self, client: httpx.AsyncClient, username: str, list_type: str) -> list[Finding]:
        """Get followers or following list."""
        findings = []
        headers = self._auth_headers()

        # Get user ID
        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
        )
        if not resp or resp.status_code != 200:
            return findings

        try:
            user_id = resp.json().get("data", {}).get("user", {}).get("id", "")
        except Exception:
            return findings

        endpoint = "followers" if list_type == "followers" else "following"
        resp2 = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/friendships/{user_id}/{endpoint}/",
            headers=headers,
            params={"count": 50},
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                users = []
                for u in data.get("users", [])[:50]:
                    users.append({
                        "username": u.get("username", ""),
                        "full_name": u.get("full_name", ""),
                        "is_verified": u.get("is_verified", False),
                        "is_private": u.get("is_private", False),
                        "profile_pic": u.get("profile_pic_url", ""),
                    })

                findings.append(Finding(
                    source=f"instagram:auth_{list_type}",
                    data_type="profile",
                    value={
                        "type": list_type,
                        "platform": "instagram",
                        "username": username,
                        "count": len(users),
                        "users": users,
                    },
                    confidence=0.95,
                    metadata={"site": "instagram", "type": list_type},
                ))
            except Exception:
                pass

        return findings

    async def _auth_api_stories(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get current stories via authenticated API."""
        findings = []
        headers = self._auth_headers()

        # Get user ID
        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
        )
        if not resp or resp.status_code != 200:
            return findings

        try:
            user_id = resp.json().get("data", {}).get("user", {}).get("id", "")
        except Exception:
            return findings

        resp2 = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/feed/user/{user_id}/story/",
            headers=headers,
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                story_items = data.get("reel", {}).get("items", [])
                if story_items:
                    stories = []
                    for item in story_items:
                        stories.append({
                            "id": item.get("id", ""),
                            "type": "video" if item.get("media_type", 0) == 2 else "image",
                            "timestamp": item.get("taken_at", 0),
                            "expires": item.get("expiring_at", 0),
                            "has_audio": item.get("has_audio", False),
                        })

                    findings.append(Finding(
                        source="instagram:auth_stories",
                        data_type="profile",
                        value={
                            "type": "stories",
                            "platform": "instagram",
                            "username": username,
                            "count": len(stories),
                            "stories": stories,
                        },
                        confidence=0.95,
                        metadata={"site": "instagram", "type": "stories"},
                    ))
            except Exception:
                pass

        return findings

    async def _auth_api_tagged(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Get tagged photos via authenticated API."""
        findings = []
        headers = self._auth_headers()

        # Get user ID
        resp = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
        )
        if not resp or resp.status_code != 200:
            return findings

        try:
            user_id = resp.json().get("data", {}).get("user", {}).get("id", "")
        except Exception:
            return findings

        resp2 = await self._make_request(
            client, "GET",
            f"https://i.instagram.com/api/v1/usertags/{user_id}/feed/",
            headers=headers,
            params={"count": 20},
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                tagged = []
                for item in data.get("items", [])[:20]:
                    tagged.append({
                        "shortcode": item.get("code", ""),
                        "url": f"https://www.instagram.com/p/{item.get('code', '')}/",
                        "username": item.get("user", {}).get("username", ""),
                        "timestamp": item.get("taken_at", 0),
                    })

                if tagged:
                    findings.append(Finding(
                        source="instagram:auth_tagged",
                        data_type="profile",
                        value={
                            "type": "tagged_photos",
                            "platform": "instagram",
                            "username": username,
                            "count": len(tagged),
                            "posts": tagged,
                        },
                        confidence=0.95,
                        metadata={"site": "instagram", "type": "tagged"},
                    ))
            except Exception:
                pass

        return findings

    def _auth_headers(self) -> dict:
        """Headers for authenticated Instagram API requests."""
        from ..core.config import USER_AGENTS
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "X-IG-App-ID": INSTAGRAM_APP_ID,
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"sessionid={self.session_id}",
            "Accept": "*/*",
        }
