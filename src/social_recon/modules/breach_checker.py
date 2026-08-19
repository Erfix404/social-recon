"""Breach checker — checks emails/phones against known breach databases.

Includes Iranian-specific breaches (Digikala, Aparat, Snapp) that HIBP doesn't cover.
"""
import asyncio
import hashlib

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import HIBP_API_KEY


# Known Iranian breaches — HIBP doesn't track these
IRANIAN_BREACHES = {
    "Digikala": {
        "year": 2022,
        "records": "4-5M",
        "data_types": ["phone", "email", "name", "address", "order_history"],
        "description": "Digikala e-commerce platform breach",
    },
    "Aparat": {
        "year": 2023,
        "records": "millions",
        "data_types": ["email", "phone", "name"],
        "description": "Aparat video platform breach",
    },
    "Snapp": {
        "year": 2023,
        "records": "millions",
        "data_types": ["phone", "name", "location"],
        "description": "Snapp ride-hailing platform breach",
    },
    "Telewebion": {
        "year": 2022,
        "records": "unknown",
        "data_types": ["email", "phone"],
        "description": "Telewebion streaming platform breach",
    },
}


class BreachChecker(BaseModule):
    """Check emails/phones against breach databases (HIBP + Iranian breaches)."""

    name = "breach_checker"
    category = ModuleCategory.BREACH
    description = "Check credentials against known breach databases"
    supported_input_types = ["email", "phone", "username"]
    requires_api_key = False  # works without API key (reduced functionality)
    api_key_env = "HIBP_API_KEY"

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Collect emails and phones from context
        emails = (context or {}).get("emails", [])
        if target_type == "email" and target not in emails:
            emails.append(target)

        phones = (context or {}).get("phones", [])
        if target_type == "phone" and target not in phones:
            phones.append(target)

        async with self.create_client() as client:
            # Check each email against HIBP
            for email in emails[:5]:
                if "noreply" in email or "github.com" in email:
                    continue
                hibp_findings = await self._check_hibp(client, email)
                findings.extend(hibp_findings)

            # Check against Iranian breach patterns (offline heuristic)
            for email in emails[:5]:
                ir_findings = self._check_iranian_breach_pattern(email, "email")
                findings.extend(ir_findings)

            for phone in phones[:3]:
                ir_findings = self._check_iranian_breach_pattern(phone, "phone")
                findings.extend(ir_findings)

            # Check breach directory API (free alternative)
            for email in emails[:3]:
                bd_findings = await self._check_breach_directory(client, email)
                findings.extend(bd_findings)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    async def _check_hibp(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Check email against Have I Been Pwned."""
        findings = []
        headers = {"User-Agent": "social-recon"}
        if HIBP_API_KEY:
            headers["hibp-api-key"] = HIBP_API_KEY

        resp = await self._make_request(
            client, "GET",
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "false"},
        )

        if resp and resp.status_code == 200:
            try:
                breaches = resp.json()
                for breach in breaches:
                    findings.append(Finding(
                        source="hibp",
                        data_type="breach",
                        value={
                            "email": email,
                            "breach_name": breach.get("Name", ""),
                            "domain": breach.get("Domain", ""),
                            "date": breach.get("BreachDate", ""),
                            "data_types": breach.get("DataClasses", []),
                            "pwn_count": breach.get("PwnCount", 0),
                            "description": breach.get("Description", "")[:200],
                        },
                        confidence=0.95,
                        metadata={"source": "hibp", "email": email},
                    ))
            except Exception:
                pass
        elif resp and resp.status_code == 404:
            findings.append(Finding(
                source="hibp",
                data_type="breach_check",
                value={"email": email, "found_in_breaches": False},
                confidence=0.8,
                metadata={"source": "hibp", "clean": True},
            ))

        return findings

    async def _check_breach_directory(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        """Check BreachDirectory API (free tier)."""
        findings = []
        email_hash = hashlib.sha1(email.encode()).hexdigest()[:5]

        resp = await self._make_request(
            client, "GET",
            f"https://api.breached.email/search/{email}",
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("found"):
                    for entry in data.get("results", [])[:5]:
                        findings.append(Finding(
                            source="breach_directory",
                            data_type="breach",
                            value={
                                "email": email,
                                "source": entry.get("source", ""),
                                "password_hash": entry.get("hash", "")[:10] + "...",
                            },
                            confidence=0.7,
                            metadata={"source": "breach_directory"},
                        ))
            except Exception:
                pass

        return findings

    def _check_iranian_breach_pattern(self, value: str, value_type: str) -> list[Finding]:
        """Check if the value matches known Iranian breach patterns.

        This is a heuristic check — we flag which Iranian breaches might contain
        this data based on the data type. For actual breach data, you'd need the
        leaked databases (not included for legal reasons).
        """
        findings = []

        for breach_name, breach_info in IRANIAN_BREACHES.items():
            matches = False
            if value_type == "email" and "email" in breach_info["data_types"]:
                matches = True
            elif value_type == "phone" and "phone" in breach_info["data_types"]:
                # Check if it's an Iranian phone number
                clean = value.replace("+98", "0").replace(" ", "")
                if clean.startswith("09") and len(clean) == 11:
                    matches = True

            if matches:
                findings.append(Finding(
                    source=f"iranian_breach:{breach_name}",
                    data_type="breach_risk",
                    value={
                        "breach": breach_name,
                        "year": breach_info["year"],
                        "data_types": breach_info["data_types"],
                        "description": breach_info["description"],
                        "note": f"{value_type} pattern matches this breach's data types",
                    },
                    confidence=0.3,  # Low confidence — pattern match, not confirmed
                    metadata={"source": "iranian_breach_heuristic", "type": value_type},
                ))

        return findings
