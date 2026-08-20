"""Cloud/S3 bucket enumeration — AWS, GCP, Azure, DigitalOcean."""
import asyncio
import re

import httpx

from .base import BaseModule, ModuleResult, Finding, ModuleCategory


# Bucket name patterns to try
BUCKET_PATTERNS = [
    "{name}", "{name}-dev", "{name}-staging", "{name}-prod", "{name}-production",
    "{name}-backup", "{name}-backups", "{name}-logs", "{name}-assets",
    "{name}-uploads", "{name}-media", "{name}-static", "{name}-cdn",
    "{name}-data", "{name}-storage", "{name}-files", "{name}-docs",
    "{name}-archive", "{name}-temp", "{name}-test", "{name}-old",
    "{name}-new", "{name}-www", "{name}-api", "{name}-app",
    "{name}dev", "{name}staging", "{name}prod", "{name}backup",
    "{name}.dev", "{name}.staging", "{name}.prod",
    "www-{name}", "dev-{name}", "staging-{name}", "prod-{name}",
    "{name}-assets-prod", "{name}-images", "{name}-video",
]

# S3-compatible endpoints
S3_ENDPOINTS = {
    "aws": "https://{bucket}.s3.amazonaws.com",
    "gcp": "https://storage.googleapis.com/{bucket}",
    "digitalocean": "https://{bucket}.nyc3.digitaloceanspaces.com",
    "azure": "https://{blob}.blob.core.windows.net",
}


class CloudEnum(BaseModule):
    """Enumerate cloud storage buckets and check permissions."""

    name = "cloud_enum"
    category = ModuleCategory.INFRASTRUCTURE
    description = "S3/GCP/Azure/DigitalOcean bucket enumeration and permission probing"
    supported_input_types = ["domain", "username"]

    def __init__(self, config=None):
        super().__init__(config)
        self.max_buckets = (config or {}).get("max_buckets", 50)

    async def run(self, target: str, target_type: str, context: dict = None) -> ModuleResult:
        findings = []
        errors = []

        # Generate bucket names from target
        name = target.replace(".com", "").replace(".ir", "").replace(".org", "").replace(".net", "")
        name = re.sub(r'[^a-z0-9\-]', '', name.lower())

        bucket_names = []
        for pattern in BUCKET_PATTERNS[:self.max_buckets]:
            bucket_names.append(pattern.format(name=name))

        # Also try usernames from context
        for username in (context or {}).get("usernames", [])[:3]:
            clean = re.sub(r'[^a-z0-9\-]', '', username.lower())
            if clean and clean != name:
                bucket_names.append(clean)
                bucket_names.append(f"{clean}-backup")
                bucket_names.append(f"{clean}-assets")

        # Remove duplicates
        bucket_names = list(dict.fromkeys(bucket_names))[:self.max_buckets]

        async with self.create_client() as client:
            # Check each bucket across providers
            tasks = []
            for bucket in bucket_names:
                for provider, endpoint_template in S3_ENDPOINTS.items():
                    tasks.append(self._check_bucket(client, bucket, provider, endpoint_template))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    errors.append(str(result))

        return ModuleResult(module_name=self.name, success=True, findings=findings, errors=errors)

    async def _check_bucket(
        self, client: httpx.AsyncClient, bucket: str, provider: str, endpoint_template: str,
    ) -> Finding | None:
        """Check if a bucket exists and probe permissions."""
        url = endpoint_template.format(bucket=bucket, blob=bucket)

        try:
            resp = await client.request("GET", url, timeout=8, follow_redirects=False)
        except Exception:
            return None

        status = resp.status_code
        text = resp.text[:2000] if resp.text else ""

        # Bucket exists and is listable
        if status == 200 and ("ListBucketResult" in text or "<Contents>" in text):
            # Count objects
            objects = re.findall(r'<Key>([^<]+)</Key>', text)
            return Finding(
                source=f"cloud_enum:{provider}",
                data_type="cloud_asset",
                value={
                    "provider": provider,
                    "bucket": bucket,
                    "url": url,
                    "status": "listable",
                    "objects_found": len(objects),
                    "sample_objects": objects[:10],
                    "permission": "public_read",
                },
                confidence=0.95,
                metadata={"source": "cloud_enum", "provider": provider, "type": "open_bucket"},
            )

        # Bucket exists but not listable (403 = exists but private, 404 = doesn't exist)
        elif status == 403:
            return Finding(
                source=f"cloud_enum:{provider}",
                data_type="cloud_asset",
                value={
                    "provider": provider,
                    "bucket": bucket,
                    "url": url,
                    "status": "exists_private",
                    "permission": "private",
                },
                confidence=0.7,
                metadata={"source": "cloud_enum", "provider": provider, "type": "private_bucket"},
            )

        # Access denied with specific error
        elif status == 404 and "NoSuchBucket" not in text and "NotFound" not in text:
            # Some providers return 404 for existing private buckets
            if "AccessDenied" in text or "AuthorizationRequired" in text:
                return Finding(
                    source=f"cloud_enum:{provider}",
                    data_type="cloud_asset",
                    value={
                        "provider": provider,
                        "bucket": bucket,
                        "url": url,
                        "status": "access_denied",
                    },
                    confidence=0.5,
                    metadata={"source": "cloud_enum", "provider": provider},
                )

        return None
