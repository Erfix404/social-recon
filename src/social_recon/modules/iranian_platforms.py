"""Iranian platform modules — 25+ Persian platforms for username/email/phone lookup.

This is our competitive advantage: Maigret (3000+ sites) has ZERO Iranian platforms.
We cover: messaging, jobs, shopping, content, classifieds, education, apps, services.
"""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import DEFAULT_RATE_LIMIT


# ── Platform Definitions ────────────────────────────────────────────

IRANIAN_PLATFORMS = {
    # Content & Blogging
    "virgool": {
        "url": "https://virgool.io/@{target}",
        "category": "content",
        "check_text": "user-page",
        "fail_text": ["not found", "404", "page not found"],
    },
    "aparat": {
        "url": "https://www.aparat.com/{target}",
        "api": "https://www.aparat.com/etc/api/profile/username/{target}",
        "category": "video",
        "check_text": "کاربر",
        "fail_text": ["کاربری یافت نشد", "error"],
    },
    "filimo": {
        "url": "https://www.filimo.com/search?q={target}",
        "category": "video",
    },
    # Jobs & Professional
    "jobinja": {
        "url": "https://jobinja.ir/users/{target}",
        "category": "jobs",
        "check_text": "user-info",
        "fail_text": ["not found", "404"],
    },
    "hamijar": {
        "url": "https://hamijar.ir/u/{target}",
        "category": "jobs",
        "check_text": "profile",
        "fail_text": ["not found", "404"],
    },
    "karboom": {
        "url": "https://karboom.io/u/{target}",
        "category": "jobs",
        "check_text": "profile",
        "fail_text": ["not found"],
    },
    "irantalent": {
        "url": "https://www.irantalent.com/u/{target}",
        "category": "jobs",
    },
    # Education
    "quera": {
        "url": "https://quera.org/profile/{target}",
        "category": "education",
        "check_text": "profile",
        "fail_text": ["not found", "404"],
    },
    "maktabkhooneh": {
        "url": "https://maktabkhooneh.org/profile/{target}",
        "category": "education",
    },
    "faradars": {
        "url": "https://faradars.org/search?q={target}",
        "category": "education",
    },
    # Shopping & Marketplace
    "digikala": {
        "url": "https://www.digikala.com/search/?q={target}",
        "category": "shopping",
    },
    "basalam": {
        "url": "https://basalam.com/{target}",
        "category": "shopping",
        "check_text": "seller",
        "fail_text": ["not found", "404"],
    },
    "torob": {
        "url": "https://torob.com/search/?query={target}",
        "category": "shopping",
    },
    # Classifieds
    "divar": {
        "url": "https://divar.ir/s/{target}",
        "category": "classifieds",
    },
    "sheypoor": {
        "url": "https://www.sheypoor.com/search?q={target}",
        "category": "classifieds",
    },
    # Messaging
    "eitaa": {
        "url": "https://eitaa.com/{target}",
        "category": "messaging",
        "check_text": "channel_info",
        "fail_text": ["not found", "404"],
    },
    "rubika": {
        "url": "https://rubika.ir/{target}",
        "category": "messaging",
    },
    "igap": {
        "url": "https://igap.net/{target}",
        "category": "messaging",
        "check_text": "profile",
        "fail_text": ["not found"],
    },
    "bale": {
        "url": "https://ble.ir/{target}",
        "category": "messaging",
    },
    # Apps
    "cafebazaar": {
        "url": "https://cafebazaar.ir/search?q={target}",
        "category": "apps",
    },
    "myket": {
        "url": "https://myket.ir/search?q={target}",
        "category": "apps",
    },
    # Services
    "snappfood": {
        "url": "https://snappfood.ir/search?query={target}",
        "category": "food",
    },
    "alibaba_ir": {
        "url": "https://www.alibaba.ir/search?q={target}",
        "category": "travel",
    },
    # Content / Social
    "zoomit": {
        "url": "https://www.zoomit.ir/?s={target}",
        "category": "tech",
    },
    "zoomg": {
        "url": "https://zoomg.ir/?s={target}",
        "category": "entertainment",
    },
    "technoava": {
        "url": "https://technoava.com/?s={target}",
        "category": "tech",
    },
    "bonyanat": {
        "url": "https://bonyanat.ir/?s={target}",
        "category": "religious",
    },
    "okala": {
        "url": "https://okala.ir/search/?q={target}",
        "category": "grocery",
    },
    "snapp": {
        "url": "https://snapp.ir/search?q={target}",
        "category": "services",
    },
}


class IranianPlatformScanner(BaseModule):
    """Scans 25+ Iranian platforms for username/email presence."""

    name = "iranian_platforms"
    category = ModuleCategory.IRANIAN
    description = "Scan 25+ Iranian/Persian platforms for account presence"
    supported_input_types = ["username", "email", "fullname"]

    def __init__(self, config=None, platforms: list[str] | None = None):
        super().__init__(config)
        self.platforms_to_scan = platforms or list(IRANIAN_PLATFORMS.keys())

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        target = target.replace("@", "").strip()
        findings = []
        errors = []

        async with self.create_client() as client:
            tasks = []
            for pname in self.platforms_to_scan:
                if pname in IRANIAN_PLATFORMS:
                    tasks.append(self._check_platform(client, pname, IRANIAN_PLATFORMS[pname], target))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    errors.append(str(result))
                elif result:
                    findings.append(result)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    async def _check_platform(self, client: httpx.AsyncClient, name: str, platform: dict, target: str) -> Finding | None:
        """Check if a username exists on a single platform."""
        url = platform["url"].format(target=target)

        # If there's a dedicated API, use that first (more reliable)
        if "api" in platform:
            api_url = platform["api"].format(target=target)
            resp = await self._make_request(client, "GET", api_url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if data and not data.get("error"):
                        return Finding(
                            source=f"iranian:{name}",
                            data_type="profile",
                            value={
                                "platform": name,
                                "url": url,
                                "api_data": data,
                                "category": platform.get("category", ""),
                            },
                            confidence=0.9,
                            metadata={"site": name, "method": "api"},
                        )
                except Exception:
                    pass

        # Fallback to HTTP probe
        resp = await self._make_request(client, "GET", url)
        if not resp:
            return None

        if resp.status_code != 200:
            return None

        text = resp.text.lower()
        fail_text = platform.get("fail_text", ["not found", "404", "page not found"])

        # Check if the page indicates the user doesn't exist
        for fail in fail_text:
            if fail.lower() in text:
                return None

        check_text = platform.get("check_text", "")
        if check_text and check_text.lower() in text:
            return Finding(
                source=f"iranian:{name}",
                data_type="profile",
                value={
                    "platform": name,
                    "url": url,
                    "category": platform.get("category", ""),
                },
                confidence=0.7,
                metadata={"site": name, "method": "http_probe"},
            )

        # If status 200 and no fail text, it might exist (lower confidence)
        if resp.status_code == 200 and len(resp.text) > 1000:
            return Finding(
                source=f"iranian:{name}",
                data_type="profile",
                value={
                    "platform": name,
                    "url": url,
                    "category": platform.get("category", ""),
                },
                confidence=0.4,
                metadata={"site": name, "method": "status_probe"},
            )

        return None


class AparatDeepRecon(BaseModule):
    """Deep Aparat (Iranian YouTube) reconnaissance using their public API."""

    name = "aparat_deep"
    category = ModuleCategory.IRANIAN
    description = "Deep Aparat profile analysis with video listing"
    supported_input_types = ["username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        async with self.create_client() as client:
            # Get profile
            profile_resp = await self._make_request(
                client, "GET",
                f"https://www.aparat.com/etc/api/profile/username/{target}",
            )
            if profile_resp and profile_resp.status_code == 200:
                try:
                    profile_data = profile_resp.json()
                    user_data = profile_data.get("included", [{}])
                    if user_data:
                        attrs = user_data[0].get("attributes", {})
                        findings.append(Finding(
                            source="aparat_deep",
                            data_type="profile",
                            value={
                                "platform": "aparat",
                                "url": f"https://www.aparat.com/{target}",
                                "name": attrs.get("display_name", ""),
                                "bio": attrs.get("desc", ""),
                                "followers": attrs.get("follower_cnt", 0),
                                "following": attrs.get("following_cnt", 0),
                                "videos": attrs.get("video_cnt", 0),
                                "profile_image": attrs.get("pic_s", ""),
                                "profile_image_lg": attrs.get("pic_l", ""),
                            },
                            confidence=0.95,
                            metadata={"site": "aparat", "method": "api"},
                        ))

                        # Download profile image
                        pic = attrs.get("pic_l") or attrs.get("pic_s")
                        if pic:
                            findings.append(Finding(
                                source="aparat_deep",
                                data_type="image",
                                value=pic,
                                confidence=0.9,
                                metadata={"site": "aparat", "type": "profile_image"},
                            ))

                except Exception as e:
                    errors.append(f"Aparat API parse error: {e}")

            # Get recent videos
            videos_resp = await self._make_request(
                client, "GET",
                f"https://www.aparat.com/etc/api/videolist/user/{target}",
            )
            if videos_resp and videos_resp.status_code == 200:
                try:
                    videos_data = videos_resp.json()
                    for video in (videos_data.get("included", []) or [])[:10]:
                        attrs = video.get("attributes", {})
                        findings.append(Finding(
                            source="aparat_deep",
                            data_type="profile",
                            value={
                                "type": "video",
                                "title": attrs.get("title", ""),
                                "url": f"https://www.aparat.com/v/{attrs.get('uid', '')}",
                                "views": attrs.get("visit_cnt", 0),
                                "likes": attrs.get("like_cnt", 0),
                                "duration": attrs.get("duration", 0),
                            },
                            confidence=0.95,
                            metadata={"site": "aparat", "type": "video"},
                        ))
                except Exception as e:
                    errors.append(f"Aparat videos parse error: {e}")

        return ModuleResult(
            module_name=self.name,
            success=bool(findings),
            findings=findings,
            errors=errors,
        )


def get_iranian_modules(config: dict = None) -> list[BaseModule]:
    """Factory: return all Iranian platform modules."""
    return [
        IranianPlatformScanner(config),
        AparatDeepRecon(config),
    ]
