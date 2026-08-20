"""Anti-detection utilities — proxy rotation, UA rotation, request fingerprinting."""
import random
from ..core.config import USER_AGENTS, PROXY_URL, TOR_SOCKS


def get_random_ua() -> str:
    """Get a random realistic User-Agent string."""
    return random.choice(USER_AGENTS)


def get_headers() -> dict:
    """Get randomized headers for HTTP requests."""
    return {
        "User-Agent": get_random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,fa;q=0.8",
            "fa-IR,fa;q=0.9,en;q=0.8",
            "en-GB,en;q=0.9",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
    }


def get_proxy() -> str | None:
    """Get proxy URL (from config or Tor)."""
    return PROXY_URL


def get_tor_proxy() -> dict:
    """Get Tor SOCKS proxy config for httpx."""
    return {"all://": TOR_SOCKS}


class ProxyRotator:
    """Simple proxy rotator from a list of proxies."""

    def __init__(self, proxies: list[str] | None = None):
        self.proxies = proxies or []
        self._index = 0

    def next(self) -> str | None:
        if not self.proxies:
            return PROXY_URL
        proxy = self.proxies[self._index % len(self.proxies)]
        self._index += 1
        return proxy

    def add(self, proxy: str):
        if proxy not in self.proxies:
            self.proxies.append(proxy)
