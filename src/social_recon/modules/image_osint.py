"""Image OSINT module — reverse image search and profile image analysis."""
import asyncio
import hashlib
import os
from pathlib import Path

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class ImageOSINT(BaseModule):
    """Reverse image search and profile image intelligence."""

    name = "image_osint"
    category = ModuleCategory.ENRICHMENT
    description = "Download and analyze profile images, reverse image search"
    supported_input_types = ["username", "email"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        output_dir = Path((context or {}).get("output_dir", "output"))
        img_dir = output_dir / "images"
        img_dir.mkdir(parents=True, exist_ok=True)

        async with self.create_client() as client:
            # 1. Download profile images from discovered profiles
            profiles = (context or {}).get("profiles", {})
            for site, profile_data in profiles.items():
                img_url = None
                if isinstance(profile_data, dict):
                    img_url = (profile_data.get("avatar") or
                               profile_data.get("image") or
                               profile_data.get("profile_image") or
                               profile_data.get("photo_url"))
                if img_url:
                    result = await self._download_image(client, img_url, site, img_dir)
                    if result:
                        findings.append(result)

            # 2. Try common avatar URLs
            target_clean = target.replace("@", "")
            avatar_urls = [
                (f"https://github.com/{target_clean}.png?size=200", "github"),
                (f"https://avatars.githubusercontent.com/{target_clean}", "github_v2"),
                (f"https://t.me/{target_clean}", "telegram"),  # Will extract from page
            ]

            for url, source in avatar_urls:
                result = await self._download_image(client, url, source, img_dir)
                if result:
                    findings.append(result)

            # 3. Check Gravatar
            if target_type == "email":
                gravatar_url = self._gravatar_url(target)
                result = await self._download_image(client, gravatar_url, "gravatar", img_dir)
                if result:
                    findings.append(result)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    async def _download_image(self, client: httpx.AsyncClient, url: str, name: str, img_dir: Path) -> Finding | None:
        """Download an image and return a finding."""
        try:
            resp = await self._make_request(client, "GET", url, timeout=10)
            if not resp or resp.status_code != 200:
                return None

            content = resp.content
            if len(content) < 500:
                return None

            # Determine extension from content-type
            ct = resp.headers.get("content-type", "")
            ext = "jpg"
            if "png" in ct:
                ext = "png"
            elif "webp" in ct:
                ext = "webp"
            elif "gif" in ct:
                ext = "gif"

            # Check if it's actually HTML (redirect page)
            if b"<html" in content[:500].lower():
                return None

            # Calculate hash for dedup
            img_hash = hashlib.md5(content).hexdigest()[:12]

            # Save image
            filename = f"{name}_{img_hash}.{ext}"
            filepath = img_dir / filename
            filepath.write_bytes(content)

            return Finding(
                source=f"image_download:{name}",
                data_type="image",
                value={
                    "source": name,
                    "url": url,
                    "path": str(filepath),
                    "size": len(content),
                    "hash": img_hash,
                    "format": ext,
                },
                confidence=0.8,
                metadata={"type": "profile_image", "source": name},
            )
        except Exception:
            return None

    def _gravatar_url(self, email: str) -> str:
        """Generate Gravatar URL from email."""
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?s=400&d=404"
