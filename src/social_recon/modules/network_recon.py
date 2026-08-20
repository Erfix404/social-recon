"""Network/Infrastructure reconnaissance — Shodan, Censys, DNS, SecurityTrails."""
import asyncio
import socket

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory
from ..core.config import SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET, SECURITYTRAILS_API_KEY


class ShodanRecon(BaseModule):
    """Shodan search for exposed services, ports, and vulnerabilities."""

    name = "shodan"
    category = ModuleCategory.INFRASTRUCTURE
    description = "Shodan search for IoT devices, exposed services, and CVEs"
    supported_input_types = ["domain", "username"]
    requires_api_key = True
    api_key_env = "SHODAN_API_KEY"

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        if not SHODAN_API_KEY:
            return ModuleResult(module_name=self.name, success=False, errors=["SHODAN_API_KEY not set"])

        async with self.create_client() as client:
            # Resolve domain to IP
            ips = await self._resolve_domain(target)
            if not ips:
                ips = [target] if self._is_ip(target) else []

            for ip in ips[:3]:
                # Host info
                resp = await self._make_request(
                    client, "GET",
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": SHODAN_API_KEY},
                )
                if resp and resp.status_code == 200:
                    data = resp.json()
                    findings.append(Finding(
                        source="shodan",
                        data_type="infrastructure",
                        value={
                            "ip": ip,
                            "org": data.get("org", ""),
                            "isp": data.get("isp", ""),
                            "os": data.get("os", ""),
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "hostnames": data.get("hostnames", []),
                            "country": data.get("country_name", ""),
                            "city": data.get("city", ""),
                            "last_update": data.get("last_update", ""),
                        },
                        confidence=0.9,
                        metadata={"source": "shodan", "type": "host_info"},
                    ))

                    # CVEs
                    for vuln in data.get("vulns", [])[:10]:
                        findings.append(Finding(
                            source="shodan",
                            data_type="vulnerability",
                            value={"ip": ip, "cve": vuln},
                            confidence=0.85,
                            metadata={"source": "shodan", "type": "cve"},
                        ))

            # Search for domain-related services
            resp = await self._make_request(
                client, "GET",
                "https://api.shodan.io/shodan/host/search",
                params={"key": SHODAN_API_KEY, "query": f"hostname:{target}", "limit": 10},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", [])[:5]:
                    findings.append(Finding(
                        source="shodan",
                        data_type="infrastructure",
                        value={
                            "ip": match.get("ip_str", ""),
                            "port": match.get("port"),
                            "product": match.get("product", ""),
                            "version": match.get("version", ""),
                            "banner": match.get("data", "")[:200],
                        },
                        confidence=0.8,
                        metadata={"source": "shodan", "type": "service"},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _resolve_domain(self, domain: str) -> list[str]:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
            return list(set(r[4][0] for r in result))
        except Exception:
            return []

    def _is_ip(self, s: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))


class CensysRecon(BaseModule):
    """Censys search for hosts and certificates."""

    name = "censys"
    category = ModuleCategory.INFRASTRUCTURE
    description = "Censys search for exposed hosts and certificates"
    supported_input_types = ["domain"]
    requires_api_key = True
    api_key_env = "CENSYS_API_ID"

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        if not CENSYS_API_ID or not CENSYS_API_SECRET:
            return ModuleResult(module_name=self.name, success=False, errors=["CENSYS credentials not set"])

        async with self.create_client() as client:
            # Search hosts
            resp = await self._make_request(
                client, "GET",
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": f"services.tls.certificates.leaf_data.subject.common_name: {target}", "per_page": 10},
                auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for hit in data.get("result", {}).get("hits", [])[:5]:
                    findings.append(Finding(
                        source="censys",
                        data_type="infrastructure",
                        value={
                            "ip": hit.get("ip", ""),
                            "services": [
                                {"port": s.get("port"), "service": s.get("service_name", ""), "transport": s.get("transport_protocol", "")}
                                for s in hit.get("services", [])[:10]
                            ],
                            "country": hit.get("location", {}).get("country", ""),
                            "autonomous_system": hit.get("autonomous_system", {}).get("asn", ""),
                        },
                        confidence=0.85,
                        metadata={"source": "censys", "type": "host"},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)


class SecurityTrailsRecon(BaseModule):
    """SecurityTrails for DNS history, subdomains, and WHOIS."""

    name = "securitytrails"
    category = ModuleCategory.DOMAIN
    description = "SecurityTrails DNS history, subdomain enumeration, WHOIS"
    supported_input_types = ["domain", "email"]
    requires_api_key = True
    api_key_env = "SECURITYTRAILS_API_KEY"

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        domain = target.split("@")[1] if target_type == "email" else target

        if not SECURITYTRAILS_API_KEY:
            return ModuleResult(module_name=self.name, success=False, errors=["SECURITYTRAILS_API_KEY not set"])

        headers = {"apikey": SECURITYTRAILS_API_KEY}
        base = "https://api.securitytrails.com/v1"

        async with self.create_client() as client:
            # Subdomains
            resp = await self._make_request(client, "GET", f"{base}/domain/{domain}/subdomains", headers=headers)
            if resp and resp.status_code == 200:
                subs = resp.json().get("subdomains", [])
                for sub in subs[:50]:
                    findings.append(Finding(
                        source="securitytrails",
                        data_type="subdomain",
                        value={"domain": f"{sub}.{domain}"},
                        confidence=0.9,
                        metadata={"source": "securitytrails"},
                    ))

            # WHOIS
            resp = await self._make_request(client, "GET", f"{base}/domain/{domain}/whois", headers=headers)
            if resp and resp.status_code == 200:
                whois = resp.json()
                findings.append(Finding(
                    source="securitytrails",
                    data_type="domain_info",
                    value={"domain": domain, "whois": whois},
                    confidence=0.9,
                    metadata={"source": "securitytrails", "type": "whois"},
                ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)


class DNSRecon(BaseModule):
    """DNS reconnaissance — record enumeration, zone transfer, reverse lookup."""

    name = "dns_recon"
    category = ModuleCategory.DOMAIN
    description = "DNS record enumeration, zone transfer testing, reverse lookup"
    supported_input_types = ["domain", "email"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []
        domain = target.split("@")[1] if target_type == "email" else target

        try:
            import dns.resolver
        except ImportError:
            return ModuleResult(module_name=self.name, success=False, errors=["dnspython not installed"])

        # Record types to query
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                findings.append(Finding(
                    source="dns_recon",
                    data_type="dns_record",
                    value={"domain": domain, "type": rtype, "records": records},
                    confidence=0.95,
                    metadata={"source": "dns", "record_type": rtype},
                ))
            except Exception:
                pass

        # Zone transfer test
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_server = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
                    findings.append(Finding(
                        source="dns_recon",
                        data_type="vulnerability",
                        value={
                            "type": "zone_transfer",
                            "nameserver": ns_server,
                            "domain": domain,
                            "records_count": len(list(zone.iterate_rdatasets())),
                        },
                        confidence=0.95,
                        metadata={"source": "dns", "type": "zone_transfer"},
                    ))
                except Exception:
                    pass
        except Exception:
            pass

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)
