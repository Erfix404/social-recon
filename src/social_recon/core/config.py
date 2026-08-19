"""Centralized configuration for Social-Recon."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
OUTPUT_DIR = BASE_DIR / "output"
SCRIPTS_DIR = BASE_DIR / "scripts"

# Ensure output dir exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Network ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]

DEFAULT_TIMEOUT = 15
DEFAULT_RATE_LIMIT = 5  # requests per second per source
MAX_CONCURRENT_MODULES = 8
MAX_RETRIES = 3
RETRY_BACKOFF = 1.5  # exponential backoff multiplier

# --- Proxy ---
PROXY_URL = os.environ.get("SOCIAL_RECON_PROXY", None)  # socks5://127.0.0.1:9050 for Tor
TOR_SOCKS = "socks5://127.0.0.1:9050"
I2P_PROXY = "http://127.0.0.1:4444"

# --- API Keys (from env) ---
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
HUNTER_API_KEY = os.environ.get("HUNTER_API_KEY", "")
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
TELEGRAM_API_ID = os.environ.get("TELEGRAM_API_ID", "")
TELEGRAM_API_HASH = os.environ.get("TELEGRAM_API_HASH", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")

# --- Scan Modes ---
SCAN_MODES = {
    "light": {
        "description": "Fast scan — basic username/email lookup",
        "modules": ["maigret", "deep_recon", "persian_platforms"],
        "timeout": 120,
    },
    "full": {
        "description": "Full scan — all passive modules",
        "modules": [
            "maigret", "deep_recon", "email_pipeline", "persian_platforms",
            "iranian_platforms", "instagram_pipeline", "twitter_pipeline",
            "github_advanced", "telegram_osint", "phone_intel",
        ],
        "timeout": 600,
    },
    "hawk": {
        "description": "Maximum recon — all modules including active",
        "modules": [
            "maigret", "deep_recon", "email_pipeline", "persian_platforms",
            "iranian_platforms", "instagram_pipeline", "twitter_pipeline",
            "github_advanced", "telegram_osint", "phone_intel",
            "breach_checker", "google_dorking", "infrastructure_recon",
            "network_recon", "secret_scanner", "deep_web_search",
            "leak_checker", "cert_transparency", "s3_enum",
        ],
        "timeout": 1200,
    },
}

# --- Iranian Phone Operator Prefixes ---
IRAN_OPERATORS = {
    "IR-MCI": {
        "name": "همراه اول",
        "prefixes": ["0910", "0911", "0912", "0913", "0914", "0915", "0916", "0917", "0918", "0919",
                      "0990", "0991", "0992", "0993", "0994"],
    },
    "Irancell": {
        "name": "ایرانسل",
        "prefixes": ["0900", "0901", "0902", "0903", "0904", "0905",
                      "0930", "0933", "0935", "0936", "0937", "0938", "0939", "0941"],
    },
    "RighTel": {
        "name": "رایتل",
        "prefixes": ["0920", "0921", "0922", "0923"],
    },
    "Taliya": {
        "name": "تالیا",
        "prefixes": ["0932"],
    },
    "Shatel": {
        "name": "شاتل موبایل",
        "prefixes": ["0998"],
    },
    "TeleKish": {
        "name": "تلکیش",
        "prefixes": ["0934"],
    },
}

# Build reverse lookup: prefix -> operator
PREFIX_TO_OPERATOR = {}
for op_key, op_data in IRAN_OPERATORS.items():
    for prefix in op_data["prefixes"]:
        PREFIX_TO_OPERATOR[prefix] = {"code": op_key, "name": op_data["name"]}
