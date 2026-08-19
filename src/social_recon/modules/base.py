"""Base module class — all OSINT modules inherit from this."""
import abc
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from enum import Enum

import httpx


class ModuleCategory(Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    SOCIAL = "social"
    INFRASTRUCTURE = "infrastructure"
    BREACH = "breach"
    IRANIAN = "iranian"
    ENRICHMENT = "enrichment"


@dataclass
class Finding:
    """A single OSINT finding with provenance."""
    source: str
    data_type: str  # "email", "phone", "username", "profile", "breach", etc.
    value: Any
    confidence: float = 0.5  # 0.0 - 1.0
    metadata: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "data_type": self.data_type,
            "value": self.value,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class ModuleResult:
    """Result container from a module execution."""
    module_name: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0
    metadata: dict = field(default_factory=dict)

    @property
    def emails(self) -> list[str]:
        return [f.value for f in self.findings if f.data_type == "email"]

    @property
    def phones(self) -> list[str]:
        return [f.value for f in self.findings if f.data_type == "phone"]

    @property
    def profiles(self) -> list[dict]:
        return [f.value for f in self.findings if f.data_type == "profile"]


class BaseModule(abc.ABC):
    """Base class for all OSINT modules.

    Subclasses MUST define:
        name: str — unique module identifier
        category: ModuleCategory — what type of module this is
        description: str — human-readable description

    And implement:
        async run(target, target_type, context) -> ModuleResult
    """

    name: str = "base"
    category: ModuleCategory = ModuleCategory.USERNAME
    description: str = "Base module"
    requires_api_key: bool = False
    api_key_env: str = ""  # environment variable name for the API key
    supported_input_types: list[str] = ["username", "email", "phone", "domain"]

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.rate_limit = self.config.get("rate_limit", 5)
        self.timeout = self.config.get("timeout", 15)
        self.proxy = self.config.get("proxy", None)
        self._last_request_time = 0.0

    async def _throttle(self):
        """Per-module rate limiting."""
        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response | None:
        """Make an HTTP request with rate limiting and retry logic."""
        await self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("follow_redirects", True)

        for attempt in range(3):
            try:
                resp = await client.request(method, url, **kwargs)
                if resp.status_code == 429:
                    wait = float(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                    await asyncio.sleep(wait)
                    continue
                return resp
            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                continue
        return None

    def create_client(self) -> httpx.AsyncClient:
        """Create an httpx client with proxy and headers."""
        from ..core.config import USER_AGENTS
        import random

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        }
        kwargs = {"headers": headers, "follow_redirects": True}
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return httpx.AsyncClient(**kwargs)

    @abc.abstractmethod
    async def run(
        self,
        target: str,
        target_type: str,
        context: dict | None = None,
    ) -> ModuleResult:
        """Execute the module. Must be implemented by subclasses."""
        ...

    def is_applicable(self, target_type: str) -> bool:
        """Check if this module should run for the given input type."""
        return target_type in self.supported_input_types

    def check_api_key(self) -> bool:
        """Check if required API key is available."""
        if not self.requires_api_key:
            return True
        import os
        return bool(os.environ.get(self.api_key_env, ""))
