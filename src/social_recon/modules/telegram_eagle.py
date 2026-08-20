"""Telegram Eagle Eye — the most powerful Telegram OSINT module.

Capabilities:
- MTProto integration via Telethon (phone lookup, profile, members)
- Channel deep analysis (admins, members, messages, engagement)
- TGStat API for channel statistics
- Telegram search engines (Lyzem, TelegramDB, Telegago)
- Profile picture history, forward tracing
- Iranian Telegram OSINT

Requires: TELEGRAM_API_ID and TELEGRAM_API_HASH env vars for MTProto features.
Without them, falls back to HTTP-based scraping (limited but still powerful).
"""
import asyncio
import re
import time
from datetime import datetime

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import TELEGRAM_API_ID, TELEGRAM_API_HASH


class TelegramEagleEye(BaseModule):
    """Comprehensive Telegram OSINT — MTProto + HTTP + Search Engines."""

    name = "telegram_eagle"
    category = ModuleCategory.SOCIAL
    description = "Eagle-eye Telegram recon: MTProto, channel analysis, phone lookup, search engines"
    supported_input_types = ["username", "phone", "email"]

    def __init__(self, config=None):
        super().__init__(config)
        self.has_mtproto = bool(TELEGRAM_API_ID and TELEGRAM_API_HASH)
        self._client = None

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        target = target.replace("@", "").strip()

        async with self.create_client() as http_client:
            # Run all non-MTProto tasks concurrently
            tasks = [
                self._scrape_tme(http_client, target),
                self._check_tgstat(http_client, target),
                self._search_engines(http_client, target),
                self._search_google_dorks(http_client, target),
            ]

            # Add MTProto tasks if available
            if self.has_mtproto:
                tasks.append(self._mtproto_lookup(target, target_type, context))

            # Add phone-specific tasks
            if target_type == "phone" or (context and context.get("phones")):
                phones = [target] if target_type == "phone" else context.get("phones", [])[:3]
                for phone in phones:
                    tasks.append(self._phone_to_telegram(http_client, phone))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Finding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    errors.append(str(result))

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.source}:{str(f.value)[:80]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=unique,
            errors=errors,
        )

    # ── HTTP-based Methods ──────────────────────────────────────────

    async def _scrape_tme(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Scrape t.me public page for profile/channel info."""
        findings = []
        resp = await self._make_request(client, "GET", f"https://t.me/{username}")
        if not resp or resp.status_code != 200 or "tgme_page_title" not in resp.text:
            return findings

        text = resp.text

        title = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', text)
        desc = re.search(r'tgme_page_description[^>]*>(.*?)</div>', text, re.DOTALL)
        photo = re.search(r'<img[^>]+src="([^"]+)"[^>]*class="tgme_page_photo_image"', text)
        members = re.search(r'([\d\s,]+)\s*(?:subscriber|member|عضو)', text)
        extra = re.search(r'tgme_page_extra[^>]*>([^<]+)', text)

        # Detect type
        page_type = "user"
        if "channel" in text.lower() or "کانال" in text:
            page_type = "channel"
        elif "group" in text.lower() or "گروه" in text:
            page_type = "group"
        elif "bot" in text.lower() or "بات" in text:
            page_type = "bot"

        profile = {
            "platform": "telegram",
            "type": page_type,
            "username": username,
            "url": f"https://t.me/{username}",
            "title": title.group(1).strip() if title else None,
            "description": re.sub(r'<[^>]+>', '', desc.group(1)).strip()[:500] if desc else None,
            "photo_url": photo.group(1) if photo else None,
            "members": members.group(1).strip().replace(" ", "").replace(",", "") if members else None,
            "extra": extra.group(1).strip() if extra else None,
        }

        findings.append(Finding(
            source="telegram_eagle:tme",
            data_type="profile",
            value=profile,
            confidence=0.85,
            metadata={"site": "telegram", "method": "tme_scrape", "type": page_type},
        ))

        if photo:
            findings.append(Finding(
                source="telegram_eagle:tme",
                data_type="image",
                value=photo.group(1),
                confidence=0.9,
                metadata={"site": "telegram", "type": "profile_photo"},
            ))

        return findings

    async def _check_tgstat(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Check TGStat for channel statistics — ir.tgstat.com for Iran."""
        findings = []

        for domain in ["ir.tgstat.com", "tgstat.com"]:
            resp = await self._make_request(
                client, "GET",
                f"https://{domain}/channel/@{username}",
            )
            if not resp or resp.status_code != 200:
                continue

            text = resp.text
            if "channel-title" not in text and "channel-header" not in text:
                continue

            # Extract stats with regex
            subscribers = re.search(r'([\d,]+)\s*(?:subscriber|member|دنبال|عضو)', text)
            posts = re.search(r'([\d,]+)\s*(?:post|پست)', text)
            avg_views = re.search(r'([\d,]+)\s*(?:avg|میانگین).*?(?:view|بازدید)', text)
            err = re.search(r'([\d.]+)%?\s*(?:ERR|engagement)', text)

            findings.append(Finding(
                source=f"telegram_eagle:tgstat:{domain}",
                data_type="profile",
                value={
                    "platform": "telegram",
                    "source": "tgstat",
                    "domain": domain,
                    "username": username,
                    "url": f"https://{domain}/channel/@{username}",
                    "subscribers": subscribers.group(1).replace(",", "") if subscribers else None,
                    "posts": posts.group(1).replace(",", "") if posts else None,
                    "avg_views": avg_views.group(1).replace(",", "") if avg_views else None,
                    "engagement_rate": err.group(1) if err else None,
                },
                confidence=0.85,
                metadata={"site": "tgstat", "method": "web_scrape"},
            ))
            break

        return findings

    async def _search_engines(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Search Telegram-specific search engines."""
        findings = []

        # TelegramDB Search
        resp = await self._make_request(
            client, "GET",
            f"https://telegramdb.org/search/{username}",
        )
        if resp and resp.status_code == 200:
            text = resp.text
            # Extract results
            channels = re.findall(r'href="(https://t\.me/[^"]+)"[^>]*>([^<]+)', text)
            for url, name in channels[:10]:
                findings.append(Finding(
                    source="telegram_eagle:telegramdb",
                    data_type="profile",
                    value={
                        "platform": "telegram",
                        "source": "telegramdb",
                        "name": name.strip(),
                        "url": url,
                    },
                    confidence=0.6,
                    metadata={"site": "telegramdb", "method": "search"},
                ))

        # Lyzem search
        resp = await self._make_request(
            client, "GET",
            f"https://lyzem.com/search?q={username}",
        )
        if resp and resp.status_code == 200:
            links = re.findall(r'href="(https://t\.me/[^"]+)"', resp.text)
            names = re.findall(r'class="[^"]*channel[^"]*name[^"]*"[^>]*>([^<]+)', resp.text)

            for i, link in enumerate(links[:5]):
                name = names[i].strip() if i < len(names) else ""
                findings.append(Finding(
                    source="telegram_eagle:lyzem",
                    data_type="search_hit",
                    value={
                        "source": "lyzem",
                        "url": link,
                        "name": name,
                        "query": username,
                    },
                    confidence=0.5,
                    metadata={"site": "lyzem", "method": "search"},
                ))

        return findings

    async def _search_google_dorks(self, client: httpx.AsyncClient, username: str) -> list[Finding]:
        """Google Dorking for Telegram content."""
        findings = []

        dorks = [
            f'site:t.me "{username}"',
            f'site:telegram.me "{username}"',
            f'"{username}" telegram کانال گروه',
            f'site:t.me inurl:{username}',
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

                for i, link in enumerate(links[:3]):
                    if "duckduckgo.com" not in link and ("t.me/" in link or "telegram.me/" in link):
                        snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:150]
                        findings.append(Finding(
                            source="telegram_eagle:dork",
                            data_type="search_hit",
                            value={"url": link, "snippet": snippet, "query": dork[:50]},
                            confidence=0.5,
                            metadata={"type": "telegram_dork"},
                        ))
            await asyncio.sleep(1)

        return findings

    async def _phone_to_telegram(self, client: httpx.AsyncClient, phone: str) -> list[Finding]:
        """Check if a phone number has Telegram via t.me."""
        findings = []
        clean = phone.replace("+98", "0").replace(" ", "").replace("-", "")

        # Try t.me with the phone number
        resp = await self._make_request(client, "GET", f"https://t.me/{clean}")
        if resp and resp.status_code == 200 and "tgme_page_title" in resp.text:
            title = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', resp.text)
            findings.append(Finding(
                source="telegram_eagle:phone",
                data_type="profile",
                value={
                    "platform": "telegram",
                    "phone": phone,
                    "url": f"https://t.me/{clean}",
                    "title": title.group(1).strip() if title else None,
                    "method": "phone_tme",
                },
                confidence=0.6,
                metadata={"site": "telegram", "method": "phone_lookup"},
            ))

        return findings

    # ── MTProto Methods (requires API credentials) ──────────────────

    async def _mtproto_lookup(self, target: str, target_type: str, context: dict = None) -> list[Finding]:
        """Deep Telegram recon via MTProto (Telethon)."""
        findings = []

        try:
            from telethon import TelegramClient
            from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
            from telethon.tl.types import InputPhoneContact
            from telethon.tl.functions.channels import GetFullChannelRequest, GetParticipantsRequest
            from telethon.tl.types import ChannelParticipantsAdmins, ChannelParticipantsSearch
        except ImportError:
            return [Finding(
                source="telegram_eagle:mtproto",
                data_type="error",
                value={"error": "Telethon not installed. Run: pip install telethon"},
                confidence=0,
                metadata={"missing_dependency": "telethon"},
            )]

        try:
            client = TelegramClient(
                'social_recon_session',
                int(TELEGRAM_API_ID),
                TELEGRAM_API_HASH,
            )
            await client.connect()

            if not await client.is_user_authorized():
                findings.append(Finding(
                    source="telegram_eagle:mtproto",
                    data_type="error",
                    value={"error": "MTProto session not authorized. Run auth flow first."},
                    confidence=0,
                    metadata={"needs_auth": True},
                ))
                await client.disconnect()
                return findings

            # Username lookup
            if target_type in ("username", "email"):
                user_findings = await self._mtproto_user_lookup(client, target)
                findings.extend(user_findings)

            # Phone lookup
            if target_type == "phone":
                phone_findings = await self._mtproto_phone_lookup(client, target)
                findings.extend(phone_findings)

            # Channel deep analysis
            channel_findings = await self._mtproto_channel_analysis(client, target)
            findings.extend(channel_findings)

            await client.disconnect()

        except Exception as e:
            findings.append(Finding(
                source="telegram_eagle:mtproto",
                data_type="error",
                value={"error": str(e)[:200]},
                confidence=0,
                metadata={"error": True},
            ))

        return findings

    async def _mtproto_user_lookup(self, client, username: str) -> list[Finding]:
        """Lookup user via MTProto."""
        findings = []

        try:
            entity = await client.get_entity(username)

            profile = {
                "platform": "telegram",
                "id": entity.id,
                "username": getattr(entity, 'username', None),
                "first_name": getattr(entity, 'first_name', None),
                "last_name": getattr(entity, 'last_name', None),
                "phone": getattr(entity, 'phone', None),
                "bot": getattr(entity, 'bot', False),
                "verified": getattr(entity, 'verified', False),
                "restricted": getattr(entity, 'restricted', False),
                "scam": getattr(entity, 'scam', False),
                "fake": getattr(entity, 'fake', False),
                "premium": getattr(entity, 'premium', False),
                "lang_code": getattr(entity, 'lang_code', None),
            }

            findings.append(Finding(
                source="telegram_eagle:mtproto",
                data_type="profile",
                value=profile,
                confidence=0.95,
                metadata={"site": "telegram", "method": "mtproto_user_lookup"},
            ))

            # Download profile photos
            photos = await client.get_profile_photos(entity, limit=5)
            for i, photo in enumerate(photos):
                findings.append(Finding(
                    source="telegram_eagle:mtproto",
                    data_type="image",
                    value={
                        "type": "profile_photo",
                        "index": i,
                        "id": photo.id,
                        "date": str(photo.date) if photo.date else None,
                        "dc_id": photo.dc_id,
                    },
                    confidence=0.9,
                    metadata={"site": "telegram", "type": "profile_photo", "index": i},
                ))

            # Get full user info
            full = await client.get_entity(username)
            if hasattr(full, 'about') and full.about:
                findings.append(Finding(
                    source="telegram_eagle:mtproto",
                    data_type="profile",
                    value={"bio": full.about},
                    confidence=0.95,
                    metadata={"site": "telegram", "type": "bio"},
                ))

        except Exception as e:
            findings.append(Finding(
                source="telegram_eagle:mtproto",
                data_type="error",
                value={"error": f"User lookup failed: {str(e)[:100]}"},
                confidence=0,
            ))

        return findings

    async def _mtproto_phone_lookup(self, client, phone: str) -> list[Finding]:
        """Resolve phone number to Telegram user via MTProto ImportContacts."""
        findings = []

        try:
            from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
            from telethon.tl.types import InputPhoneContact

            # Normalize phone
            clean = phone.replace("+98", "0").replace(" ", "").replace("-", "")
            if not clean.startswith("+"):
                clean = "+98" + clean.lstrip("0") if clean.startswith("09") else "+" + clean

            contact = InputPhoneContact(client_id=0, phone=clean, first_name='OSINT', last_name='Check')
            result = await client(ImportContactsRequest([contact]))

            if result.users:
                user = result.users[0]
                findings.append(Finding(
                    source="telegram_eagle:mtproto_phone",
                    data_type="profile",
                    value={
                        "platform": "telegram",
                        "id": user.id,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "username": user.username,
                        "phone": user.phone,
                        "bot": user.bot,
                        "verified": user.verified,
                        "scam": user.scam,
                        "fake": user.fake,
                        "premium": getattr(user, 'premium', False),
                    },
                    confidence=0.95,
                    metadata={"site": "telegram", "method": "mtproto_phone_lookup"},
                ))

                # Clean up — remove the contact we just added
                try:
                    await client(DeleteContactsRequest([user]))
                except Exception:
                    pass

        except Exception as e:
            if "FLOOD_WAIT" in str(e):
                findings.append(Finding(
                    source="telegram_eagle:mtproto_phone",
                    data_type="error",
                    value={"error": f"Rate limited: {str(e)[:100]}"},
                    confidence=0,
                ))
            else:
                findings.append(Finding(
                    source="telegram_eagle:mtproto_phone",
                    data_type="error",
                    value={"error": f"Phone lookup failed: {str(e)[:100]}"},
                    confidence=0,
                ))

        return findings

    async def _mtproto_channel_analysis(self, client, username: str) -> list[Finding]:
        """Deep channel/group analysis via MTProto."""
        findings = []

        try:
            from telethon.tl.functions.channels import GetFullChannelRequest, GetParticipantsRequest
            from telethon.tl.types import ChannelParticipantsAdmins, ChannelParticipantsSearch

            entity = await client.get_entity(username)

            # Check if it's a channel
            if not hasattr(entity, 'megagroup') and not hasattr(entity, 'broadcast'):
                return findings

            # Get full channel info
            full = await client(GetFullChannelRequest(entity))

            channel_info = {
                "platform": "telegram",
                "type": "channel",
                "id": entity.id,
                "title": entity.title,
                "username": getattr(entity, 'username', None),
                "megagroup": getattr(entity, 'megagroup', False),
                "broadcast": getattr(entity, 'broadcast', False),
                "verified": getattr(entity, 'verified', False),
                "scam": getattr(entity, 'scam', False),
                "participants_count": full.full_chat.participants_count,
                "about": full.full_chat.about,
            }

            findings.append(Finding(
                source="telegram_eagle:mtproto_channel",
                data_type="profile",
                value=channel_info,
                confidence=0.95,
                metadata={"site": "telegram", "method": "mtproto_channel"},
            ))

            # Get admins
            try:
                admins = await client.get_participants(entity, filter=ChannelParticipantsAdmins())
                for admin in admins:
                    findings.append(Finding(
                        source="telegram_eagle:mtproto_channel",
                        data_type="profile",
                        value={
                            "type": "channel_admin",
                            "channel": username,
                            "user_id": admin.id,
                            "username": admin.username,
                            "first_name": admin.first_name,
                            "last_name": admin.last_name,
                            "bot": admin.bot,
                        },
                        confidence=0.9,
                        metadata={"site": "telegram", "type": "admin", "channel": username},
                    ))
            except Exception:
                pass

            # Get recent messages for engagement analysis
            try:
                messages = await client.get_messages(entity, limit=50)
                if messages:
                    total_views = sum(m.views or 0 for m in messages)
                    total_forwards = sum(m.forwards or 0 for m in messages)
                    avg_views = total_views / len(messages) if messages else 0
                    avg_forwards = total_forwards / len(messages) if messages else 0

                    findings.append(Finding(
                        source="telegram_eagle:mtproto_channel",
                        data_type="profile",
                        value={
                            "type": "channel_analytics",
                            "channel": username,
                            "messages_analyzed": len(messages),
                            "avg_views": round(avg_views),
                            "avg_forwards": round(avg_forwards, 1),
                            "engagement_rate": round(avg_views / full.full_chat.participants_count * 100, 2) if full.full_chat.participants_count else 0,
                            "total_views": total_views,
                        },
                        confidence=0.9,
                        metadata={"site": "telegram", "type": "analytics"},
                    ))

                    # Forward analysis — where does this channel forward from?
                    forward_sources = {}
                    for msg in messages:
                        if msg.fwd_from and msg.fwd_from.from_id:
                            src_id = msg.fwd_from.from_id
                            forward_sources[str(src_id)] = forward_sources.get(str(src_id), 0) + 1

                    if forward_sources:
                        findings.append(Finding(
                            source="telegram_eagle:mtproto_channel",
                            data_type="profile",
                            value={
                                "type": "forward_analysis",
                                "channel": username,
                                "forward_sources": forward_sources,
                                "total_forwards_analyzed": sum(forward_sources.values()),
                            },
                            confidence=0.85,
                            metadata={"site": "telegram", "type": "forward_network"},
                        ))
            except Exception:
                pass

        except Exception as e:
            findings.append(Finding(
                source="telegram_eagle:mtproto_channel",
                data_type="error",
                value={"error": f"Channel analysis failed: {str(e)[:100]}"},
                confidence=0,
            ))

        return findings
