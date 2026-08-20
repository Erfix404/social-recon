"""Wayback Machine, Common Crawl, and metadata extraction."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


class WaybackRecon(BaseModule):
    """Wayback Machine CDX API + Common Crawl for historical data."""

    name = "wayback"
    category = ModuleCategory.ENRICHMENT
    description = "Wayback Machine and Common Crawl historical data mining"
    supported_input_types = ["domain", "username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        async with self.create_client() as client:
            # Wayback Machine CDX API
            wb_findings = await self._query_wayback(client, target)
            findings.extend(wb_findings)

            # Common Crawl
            cc_findings = await self._query_common_crawl(client, target)
            findings.extend(cc_findings)

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _query_wayback(self, client: httpx.AsyncClient, target: str) -> list[Finding]:
        """Query Wayback Machine CDX API."""
        findings = []

        resp = await self._make_request(
            client, "GET",
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{target}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": 100,
            },
            timeout=30,
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if len(data) > 1:  # First row is headers
                    headers = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers, row))
                        findings.append(Finding(
                            source="wayback",
                            data_type="historical_url",
                            value={
                                "url": entry.get("original", ""),
                                "timestamp": entry.get("timestamp", ""),
                                "status": entry.get("statuscode", ""),
                                "mimetype": entry.get("mimetype", ""),
                                "archive_url": f"https://web.archive.org/web/{entry.get('timestamp', '')}/{entry.get('original', '')}",
                            },
                            confidence=0.8,
                            metadata={"source": "wayback"},
                        ))

                    findings.append(Finding(
                        source="wayback",
                        data_type="domain_info",
                        value={
                            "domain": target,
                            "total_snapshots": len(data) - 1,
                            "type": "wayback_summary",
                        },
                        confidence=0.9,
                        metadata={"source": "wayback", "type": "summary"},
                    ))
            except Exception:
                pass

        return findings

    async def _query_common_crawl(self, client: httpx.AsyncClient, target: str) -> list[Finding]:
        """Query Common Crawl index."""
        findings = []

        # Try latest index
        indexes = ["CC-MAIN-2025-05", "CC-MAIN-2024-51", "CC-MAIN-2024-46"]
        for index in indexes[:1]:
            resp = await self._make_request(
                client, "GET",
                f"https://index.commoncrawl.org/{index}-index",
                params={"url": f"{target}/*", "output": "json", "limit": 50},
                timeout=30,
            )
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split("\n")[:50]:
                    try:
                        import json
                        entry = json.loads(line)
                        findings.append(Finding(
                            source="common_crawl",
                            data_type="historical_url",
                            value={
                                "url": entry.get("url", ""),
                                "timestamp": entry.get("timestamp", ""),
                                "status": entry.get("status", ""),
                                "mime": entry.get("mime", ""),
                                "filename": entry.get("filename", ""),
                            },
                            confidence=0.75,
                            metadata={"source": "common_crawl", "index": index},
                        ))
                    except Exception:
                        continue
                break

        return findings


class MetadataExtractor(BaseModule):
    """Extract metadata from public documents and images."""

    name = "metadata"
    category = ModuleCategory.ENRICHMENT
    description = "Metadata extraction from documents, images, and public files"
    supported_input_types = ["domain", "username"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Check for downloaded images from other modules
        output_dir = (context or {}).get("output_dir", "output")
        import os
        img_dir = os.path.join(output_dir, "images")

        if os.path.exists(img_dir):
            for filename in os.listdir(img_dir):
                filepath = os.path.join(img_dir, filename)
                meta = await self._extract_exif(filepath)
                if meta:
                    findings.append(Finding(
                        source="metadata:exif",
                        data_type="metadata",
                        value={
                            "file": filename,
                            "path": filepath,
                            "metadata": meta,
                        },
                        confidence=0.9,
                        metadata={"source": "exiftool", "file": filename},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _extract_exif(self, filepath: str) -> dict | None:
        """Extract EXIF metadata using exiftool."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "exiftool", "-json", "-G", filepath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if proc.returncode == 0 and stdout:
                import json
                data = json.loads(stdout)
                if data:
                    # Filter interesting fields
                    meta = data[0]
                    interesting = {}
                    for key in ["GPS", "Camera", "Date", "Author", "Creator", "Software", "ImageWidth", "ImageHeight"]:
                        for k, v in meta.items():
                            if key.lower() in k.lower() and v:
                                interesting[k] = str(v)[:200]
                    return interesting if interesting else None
        except FileNotFoundError:
            pass  # exiftool not installed
        except Exception:
            pass
        return None


class GeolocationOSINT(BaseModule):
    """Geolocation intelligence from various sources."""

    name = "geolocation"
    category = ModuleCategory.ENRICHMENT
    description = "Geolocation from IP, domain, and social media metadata"
    supported_input_types = ["domain", "username", "phone"]

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        async with self.create_client() as client:
            # IP geolocation for domains
            if target_type == "domain":
                import socket
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, target)
                    geo = await self._ip_geolocation(client, ip)
                    if geo:
                        findings.append(Finding(
                            source="geolocation:ip-api",
                            data_type="geolocation",
                            value={"domain": target, "ip": ip, **geo},
                            confidence=0.8,
                            metadata={"source": "ip-api"},
                        ))
                except Exception:
                    pass

            # Iranian phone geolocation
            if target_type == "phone":
                phone = target.replace("+98", "0").replace(" ", "")
                if phone.startswith("09"):
                    from ..core.config import PREFIX_TO_OPERATOR
                    prefix = phone[:4]
                    op = PREFIX_TO_OPERATOR.get(prefix, {})
                    findings.append(Finding(
                        source="geolocation:phone",
                        data_type="geolocation",
                        value={
                            "phone": phone,
                            "country": "Iran",
                            "operator": op.get("name", "Unknown"),
                            "operator_code": op.get("code", ""),
                        },
                        confidence=0.9,
                        metadata={"source": "phone_prefix"},
                    ))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _ip_geolocation(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        """Get IP geolocation from ip-api.com (free, unlimited)."""
        resp = await self._make_request(client, "GET", f"http://ip-api.com/json/{ip}")
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", ""),
                    "proxy": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                }
        return None
