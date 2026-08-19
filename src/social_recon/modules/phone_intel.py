"""Phone intelligence module — Iranian operator ID, OSINT lookup, dorking."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import PREFIX_TO_OPERATOR, IRAN_OPERATORS


class PhoneIntel(BaseModule):
    """Phone number intelligence: operator identification, OSINT dorking, Telegram lookup."""

    name = "phone_intel"
    category = ModuleCategory.PHONE
    description = "Phone number intelligence — operator ID, OSINT dorks, social media lookup"
    supported_input_types = ["phone"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Normalize phone
        phone = self._normalize_iranian_phone(target)

        # 1. Operator identification
        operator = self._identify_operator(phone)
        if operator:
            findings.append(Finding(
                source="phone_intel",
                data_type="phone_info",
                value={
                    "phone": phone,
                    "operator_code": operator["code"],
                    "operator_name": operator["name"],
                    "country": "IR",
                    "is_mobile": True,
                },
                confidence=0.95,
                metadata={"type": "operator_identification"},
            ))

        # 2. Check if it's a valid Iranian mobile
        if phone.startswith("09") and len(phone) == 11:
            findings.append(Finding(
                source="phone_intel",
                data_type="phone_info",
                value={"phone": phone, "valid_iranian_mobile": True},
                confidence=0.9,
                metadata={"type": "validation"},
            ))

        # 3. OSINT dorking for the phone number
        async with self.create_client() as client:
            dork_findings = await self._run_phone_dorks(client, phone, context)
            findings.extend(dork_findings)

            # 4. Check if phone is linked to social media
            social_findings = await self._check_social_links(client, phone)
            findings.extend(social_findings)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    def _normalize_iranian_phone(self, phone: str) -> str:
        """Normalize phone to 09XXXXXXXXX format."""
        phone = re.sub(r'[\s\-\(\)]', '', phone)
        if phone.startswith("+98"):
            phone = "0" + phone[3:]
        elif phone.startswith("98") and len(phone) >= 12:
            phone = "0" + phone[2:]
        elif phone.startswith("0098"):
            phone = "0" + phone[4:]
        if not phone.startswith("0") and len(phone) == 10 and phone.startswith("9"):
            phone = "0" + phone
        return phone

    def _identify_operator(self, phone: str) -> dict | None:
        """Identify Iranian mobile operator from phone prefix."""
        # Try 4-digit prefix first, then 3-digit
        for prefix_len in (4, 3):
            prefix = phone[:prefix_len + 1]  # +1 for the leading 0
            if prefix in PREFIX_TO_OPERATOR:
                return PREFIX_TO_OPERATOR[prefix]
        return None

    async def _run_phone_dorks(self, client: httpx.AsyncClient, phone: str, context: dict = None) -> list[Finding]:
        """Run Google Dorks via DuckDuckGo for the phone number."""
        findings = []
        variations = [phone]
        if phone.startswith("09"):
            variations.append(phone[1:])  # 9XXXXXXXXX
            variations.append("+98" + phone[1:])  # +989XXXXXXXXX

        # Build dork queries
        dork_queries = []
        for v in variations[:2]:
            dork_queries.extend([
                f'"{v}" site:instagram.com',
                f'"{v}" site:telegram.me OR site:t.me',
                f'"{v}" site:divar.ir',
                f'"{v}" site:virgool.io',
                f'"{v}" موبایل OR شماره تماس',
            ])

        seen_urls = set()
        for query in dork_queries[:8]:
            try:
                resp = await self._make_request(
                    client, "GET",
                    "https://html.duckduckgo.com/html/",
                    params={"q": query},
                )
                if resp and resp.status_code == 200:
                    text = resp.text
                    # Extract results
                    links = re.findall(r'class="result__a"[^>]*href="([^"]+)"', text)
                    snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', text, re.DOTALL)

                    for i, link in enumerate(links[:3]):
                        if link not in seen_urls and "duckduckgo.com" not in link:
                            seen_urls.add(link)
                            snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else '')[:150]
                            findings.append(Finding(
                                source="phone_dork",
                                data_type="search_hit",
                                value={
                                    "query": query,
                                    "url": link,
                                    "snippet": snippet,
                                    "phone": phone,
                                },
                                confidence=0.5,
                                metadata={"type": "dork_result"},
                            ))
            except Exception:
                pass
            await asyncio.sleep(1)  # Rate limit between dorks

        return findings

    async def _check_social_links(self, client: httpx.AsyncClient, phone: str) -> list[Finding]:
        """Check social platforms for phone number."""
        findings = []

        # Check t.me with phone variations
        clean_phone = phone.replace("0", "+98", 1) if phone.startswith("0") else phone
        resp = await self._make_request(client, "GET", f"https://t.me/{phone}")
        if resp and resp.status_code == 200:
            text = resp.text
            if "tgme_page_title" in text:
                title_match = re.search(r'tgme_page_title[^>]*>\s*([^<]+)', text)
                findings.append(Finding(
                    source="phone_intel:telegram",
                    data_type="profile",
                    value={
                        "platform": "telegram",
                        "url": f"https://t.me/{phone}",
                        "title": title_match.group(1).strip() if title_match else None,
                    },
                    confidence=0.6,
                    metadata={"site": "telegram", "method": "phone_tme"},
                ))

        return findings


class PhoneInfogaBridge(BaseModule):
    """Bridge to PhoneInfoga CLI tool (if installed)."""

    name = "phoneinfoga"
    category = ModuleCategory.PHONE
    description = "PhoneInfoga phone number scanner (requires CLI)"
    supported_input_types = ["phone"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        import subprocess
        findings = []
        errors = []

        phone = target.replace("+", "").replace(" ", "").replace("-", "")
        if not phone.startswith("+"):
            phone = "+98" + phone.lstrip("0") if phone.startswith("09") else "+" + phone

        try:
            proc = await asyncio.create_subprocess_exec(
                "phoneinfoga", "scan", "-n", phone, "--format", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

            if proc.returncode == 0 and stdout:
                import json
                data = json.loads(stdout)
                findings.append(Finding(
                    source="phoneinfoga",
                    data_type="phone_info",
                    value=data,
                    confidence=0.85,
                    metadata={"source": "phoneinfoga"},
                ))
        except FileNotFoundError:
            errors.append("PhoneInfoga not installed")
        except asyncio.TimeoutError:
            errors.append("PhoneInfoga timed out")
        except Exception as e:
            errors.append(f"PhoneInfoga error: {e}")

        return ModuleResult(
            module_name=self.name,
            success=bool(findings),
            findings=findings,
            errors=errors,
        )
