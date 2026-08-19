"""Certificate Transparency module — discover subdomains via CT logs."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class CertTransparency(BaseModule):
    """Discover subdomains and certificates via Certificate Transparency logs."""

    name = "cert_transparency"
    category = ModuleCategory.DOMAIN
    description = "Certificate Transparency log mining for subdomain discovery"
    supported_input_types = ["domain", "email"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Extract domain
        if target_type == "email":
            domain = target.split("@")[1]
        else:
            domain = target

        async with self.create_client() as client:
            # 1. Query crt.sh
            crt_findings = await self._query_crtsh(client, domain)
            findings.extend(crt_findings)

            # 2. Query CertSpotter (free API)
            cs_findings = await self._query_certspotter(client, domain)
            findings.extend(cs_findings)

        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
        )

    async def _query_crtsh(self, client: httpx.AsyncClient, domain: str) -> list[Finding]:
        """Query crt.sh for certificate transparency entries."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
        )
        if resp and resp.status_code == 200:
            try:
                certs = resp.json()
                seen_domains = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for d in name.split("\n"):
                        d = d.strip().lower()
                        if d and d not in seen_domains and "*" not in d:
                            seen_domains.add(d)
                            findings.append(Finding(
                                source="crtsh",
                                data_type="subdomain",
                                value={
                                    "domain": d,
                                    "issuer": cert.get("issuer_ca_id", ""),
                                    "not_before": cert.get("not_before", ""),
                                    "not_after": cert.get("not_after", ""),
                                    "serial_number": cert.get("serial_number", ""),
                                },
                                confidence=0.9,
                                metadata={"source": "crtsh", "parent_domain": domain},
                            ))

                findings.append(Finding(
                    source="crtsh",
                    data_type="domain_info",
                    value={
                        "domain": domain,
                        "total_certificates": len(certs),
                        "unique_subdomains": len(seen_domains),
                    },
                    confidence=0.95,
                    metadata={"source": "crtsh", "type": "summary"},
                ))
            except Exception as e:
                pass

        return findings

    async def _query_certspotter(self, client: httpx.AsyncClient, domain: str) -> list[Finding]:
        """Query CertSpotter free API."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=30,
        )
        if resp and resp.status_code == 200:
            try:
                certs = resp.json()
                seen = set()
                for cert in certs[:100]:
                    for d in cert.get("dns_names", []):
                        d = d.lower()
                        if d not in seen and "*" not in d:
                            seen.add(d)
                            findings.append(Finding(
                                source="certspotter",
                                data_type="subdomain",
                                value={"domain": d},
                                confidence=0.85,
                                metadata={"source": "certspotter", "parent_domain": domain},
                            ))
            except Exception:
                pass

        return findings
