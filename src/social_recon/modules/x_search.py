"""X (Twitter) search module — uses synced cookies for full GraphQL search.

This module integrates with the Hermes Cookie Sync system (or manual
TWITTER_AUTH_TOKEN/TWITTER_CT0 env vars) to perform real Twitter searches
for OSINT mentions of the target.

Key discovery (2026-08): SearchTimeline is POST-only now, and requires
the exact feature flags from the current main.js bundle.
"""
import asyncio
import json
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


# Standard web Bearer token (stable across sessions)
X_BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

# Feature flags extracted from main.dd6a5b6a.js (2026-08)
X_FEATURES = {
    "rweb_video_screen_enabled": True,
    "rweb_cashtags_enabled": True,
    "profile_label_improvements_pcf_label_in_post_enabled": True,
    "responsive_web_profile_redirect_enabled": True,
    "rweb_tipjar_consumption_enabled": True,
    "verified_phone_label_enabled": True,
    "creator_subscriptions_tweet_preview_api_enabled": True,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "premium_content_api_read_enabled": True,
    "communities_web_enable_tweet_community_results_fetch": True,
    "c9s_tweet_anatomy_moderator_badge_enabled": True,
    "responsive_web_grok_analyze_button_fetch_trends_enabled": True,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "responsive_web_grok_analyze_post_followups_enabled": True,
    "responsive_web_jetfuel_frame": True,
    "responsive_web_grok_share_attachment_enabled": True,
    "responsive_web_edit_tweet_api_enabled": True,
    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
    "view_counts_everywhere_api_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "responsive_web_twitter_article_tweet_consumption_enabled": True,
    "tweet_awards_web_tipping_enabled": False,
    "creator_subscriptions_quote_tweet_preview_enabled": False,
    "freedom_of_speech_not_reach_fetch_enabled": True,
    "standardized_nudges_misinfo": True,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "rweb_video_timestamps_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "rweb_tipjar_consumption_enabled_v2": True,
    "articles_preview_enabled": True,
    "rweb_articles_read_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
}


class XSearch(BaseModule):
    """Search X/Twitter for target mentions using cookie-based GraphQL API."""

    name = "x_search"
    category = ModuleCategory.SOCIAL
    description = "Full-text X/Twitter search for target mentions via synced cookies"
    supported_input_types = ["username", "email", "phone", "fullname"]

    def __init__(self, config=None):
        super().__init__(config)
        import os
        self.auth_token = os.environ.get("TWITTER_AUTH_TOKEN", "")
        self.ct0 = os.environ.get("TWITTER_CT0", "")

        # Try Hermes cookie sync file as fallback
        if not self.auth_token:
            try:
                sync_file = r"C:\Users\TOP\Desktop\test\hermes-cookie-sync\backend\storage_state.json"
                with open(sync_file, encoding="utf-8") as f:
                    data = json.load(f)
                cookies = [c for c in data.get("cookies", []) if "x.com" in c.get("domain", "")]
                self.auth_token = next((c["value"] for c in cookies if c["name"] == "auth_token"), "")
                self.ct0 = next((c["value"] for c in cookies if c["name"] == "ct0"), "")
            except Exception:
                pass

        self.has_auth = bool(self.auth_token and self.ct0)
        self.query_id = "hyPfJYJ_XAtDYoslQc-Rgg"  # SearchTimeline — refresh via _refresh_query_id

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        if not self.has_auth:
            errors.append("No X cookies available — set TWITTER_AUTH_TOKEN + TWITTER_CT0 or use Hermes Cookie Sync")
            return ModuleResult(module_name=self.name, success=False, findings=[], errors=errors)

        await self._refresh_query_id()

        # Build search queries based on target type
        queries = []
        clean = target.replace("@", "").strip()
        queries.append(f'"{clean}"')
        if target_type == "email":
            queries.append(f'"{target}" (استاک OR leak OR dump)')
        elif target_type == "phone":
            queries.append(f'"{target}" OR "{target.replace("+98", "09")}"')
        elif target_type == "fullname":
            queries.append(target)

        async with httpx.AsyncClient(timeout=20) as client:
            for query in queries[:3]:
                try:
                    tweets = await self._search(client, query)
                    for t in tweets[:10]:
                        findings.append(Finding(
                            source="x_search",
                            data_type="search_hit",
                            value=t,
                            confidence=0.7 if t.get("favs", 0) > 5 else 0.5,
                            metadata={"type": "x_mention", "query": query[:50]},
                        ))
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {str(e)[:100]}")
                await asyncio.sleep(1.5)

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _refresh_query_id(self):
        """Fetch fresh SearchTimeline queryId from X's JS bundle."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://x.com/search?q=test&f=live",
                    headers={"Cookie": f"auth_token={self.auth_token}; ct0={self.ct0}",
                             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                )
                js_match = re.search(r'//abs\.twimg\.com/responsive-web/client-web/main\.[\w~-]+\.js', resp.text)
                if js_match:
                    js_resp = await client.get("https:" + js_match.group(0))
                    ids = re.findall(r'queryId:"([\w-]+)",operationName:"SearchTimeline"', js_resp.text)
                    if ids:
                        self.query_id = ids[0]
        except Exception:
            pass  # Keep fallback query_id

    async def _search(self, client: httpx.AsyncClient, query: str, count: int = 20) -> list[dict]:
        """Execute a SearchTimeline POST request."""
        url = f"https://x.com/i/api/graphql/{self.query_id}/SearchTimeline"
        headers = {
            "Cookie": f"auth_token={self.auth_token}; ct0={self.ct0}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Authorization": f"Bearer {X_BEARER}",
            "x-csrf-token": self.ct0,
            "Content-Type": "application/json",
            "x-twitter-auth-type": "OAuth2Session",
        }
        payload = {
            "variables": {"rawQuery": query, "count": count, "querySource": "typed_query", "product": "Latest"},
            "features": X_FEATURES,
        }

        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        result = resp.json()

        tweets = []

        def handle_tr(tr):
            if not tr:
                return
            if tr.get("__typename") == "TweetWithVisibilityResults":
                tr = tr.get("tweet", {})
            legacy = tr.get("legacy") or {}
            note = ((tr.get("note_tweet") or {}).get("note_tweet_results") or {}).get("result") or {}
            user = (((tr.get("core") or {}).get("user_results") or {}).get("result") or {})
            user_core = user.get("core") or {}
            text = note.get("text") or legacy.get("full_text")
            if text:
                tweets.append({
                    "user": user_core.get("screen_name"),
                    "name": user_core.get("name"),
                    "text": text[:400],
                    "favs": legacy.get("favorite_count", 0),
                    "rts": legacy.get("retweet_count", 0),
                    "date": legacy.get("created_at", ""),
                    "url": f"https://x.com/{user_core.get('screen_name')}/status/{legacy.get('id_str', '')}",
                })

        instructions = (result.get("data", {}).get("search_by_raw_query", {})
                       .get("search_timeline", {}).get("timeline", {}).get("instructions", []))

        for inst in instructions:
            for entry in inst.get("entries", []):
                content = entry.get("content") or {}
                typename = content.get("__typename", "")
                if typename == "TimelineTimelineItem":
                    ic = content.get("itemContent") or {}
                    handle_tr((ic.get("tweet_results") or {}).get("result"))
                elif typename == "TimelineTimelineModule":
                    for sub in content.get("items") or []:
                        ic = (sub.get("item") or {}).get("itemContent") or {}
                        handle_tr((ic.get("tweet_results") or {}).get("result"))

        return tweets
