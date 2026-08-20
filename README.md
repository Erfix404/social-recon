# Social-Recon v2.0 — Advanced OSINT Reconnaissance Framework

A powerful OSINT tool that extracts maximum intelligence from usernames, emails, phone numbers, and domains — using **free public sources first**, with optional API enhancements.

## Philosophy: Free First

```
Layer 1: FREE (always runs)     — HTTP scraping, Google Dorking, web viewers,
                                   public APIs, DuckDuckGo, Wayback Machine
Layer 2: FREE TOOLS (optional)  — Maigret, PhoneInfoga (CLI, no API key)
Layer 3: API KEYS (optional)    — Shodan, Censys, HIBP, Telegram MTProto
```

**Every module works without API keys.** API keys only add extra depth.

## What Makes This Different

- **25+ Iranian platforms** — Aparat, Virgool, Jobinja, Quera, Digikala, Eitaa, Bale, Rubika and more. Maigret (3000+ sites) has ZERO Iranian coverage.
- **Eagle Eye modules** — Deep recon for Telegram, Instagram, and Twitter/X
- **Iranian breach database** — Checks against Digikala, Aparat, Snapp breaches that HIBP doesn't track.
- **Phone operator identification** — Instantly identify همراه اول، ایرانسل، رایتل from prefix.
- **Async pipeline** — 25 modules run concurrently for maximum speed.
- **Confidence scoring** — Multi-source corroboration with confidence labels.
- **Entity graph** — Interactive relationship visualization (vis-network.js + Mermaid).

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a scan (all free methods, no API keys needed)
python run.py <username|email|phone|domain> [light|full|hawk]

# Examples
python run.py erfix404              # Full scan on username
python run.py user@email.com hawk   # Maximum recon on email
python run.py 09123456789 hawk      # Phone scan (Iranian)
python run.py example.com hawk      # Domain scan
```

## Scan Modes

| Mode | Modules | Time | Description |
|------|---------|------|-------------|
| `light` | 4 | ~30s | Fast — Maigret + Iranian platforms + Telegram |
| `full` | 18 | ~2-5min | All passive modules (all free, no API keys) |
| `hawk` | 25 | ~5-10min | Maximum — includes active modules + API-key modules |

## Eagle Eye Modules

### Telegram Eagle Eye
- MTProto integration (Telethon) — phone lookup, channel analysis, member scraping
- TGStat API (ir.tgstat.com) — 125K+ Iranian channel stats
- Telegram search engines (TelegramDB, Lyzem)
- Google Dorking for Telegram content
- Profile picture history, forward network mapping

### Instagram Eagle Eye
- Mobile API (i.instagram.com) — HD profile pics, business info, address
- **Google Dorking for commented posts** — see where someone commented
- Web viewers (Picuki, Imginn, StoriesIG, Dumpor, Inflact)
- Tagged photos, stories, highlights detection
- Followers/following lists (with auth)

### Twitter/X Eagle Eye
- Syndication API — public tweet lookup (no auth needed)
- Nitter instances — anonymous profile/tweet viewing
- oEmbed API — embed data
- Google Dorking for tweets and replies
- Wayback Machine — deleted tweet recovery

## All Modules (25)

| Module | Mode | Free? | Description |
|--------|------|-------|-------------|
| maigret | all | ✅ | 3000+ sites username check |
| iranian_platforms | all | ✅ | 25+ Persian platforms |
| aparat_deep | all | ✅ | Aparat API deep recon |
| telegram_eagle | all | ✅ | Telegram OSINT |
| instagram_eagle | full+ | ✅ | Instagram deep recon |
| twitter_eagle | full+ | ✅ | Twitter/X recon |
| tiktok | full+ | ✅ | TikTok profile |
| reddit | full+ | ✅ | Reddit + deleted content |
| email_enricher | full+ | ✅ | Email enrichment |
| phone_intel | full+ | ✅ | Iranian operator + dorking |
| breach_checker | full+ | ✅ | HIBP + Iranian breaches |
| google_dorking | full+ | ✅ | Automated dorking |
| image_osint | full+ | ✅ | Profile images |
| wayback | full+ | ✅ | Historical data |
| geolocation | full+ | ✅ | IP + phone geo |
| dns_recon | full+ | ✅ | DNS records |
| cert_transparency | hawk | ✅ | CT log mining |
| secret_scanner | hawk | ✅ | Credential scanning |
| metadata | hawk | ✅ | EXIF extraction |
| cloud_enum | hawk | ✅ | S3/GCP/Azure buckets |
| shodan | hawk | 🔑 | IoT + ports + CVEs |
| censys | hawk | 🔑 | Host search |
| securitytrails | hawk | 🔑 | DNS history |

## Output

```
output/<target>/
├── recon_results.json    # Full JSON with confidence scores
├── report.md             # Persian report + Mermaid entity graph
├── report.html           # Interactive HTML (dark theme, charts)
├── findings.csv          # Spreadsheet export
└── images/               # Downloaded profile images
```

## Optional API Keys

```bash
export TELEGRAM_API_ID=12345          # Telegram MTProto
export TELEGRAM_API_HASH=abc123       # Telegram MTProto
export INSTAGRAM_SESSION_ID=xxx       # Instagram auth features
export SHODAN_API_KEY=xxx             # Shodan
export CENSYS_API_ID=xxx              # Censys
export CENSYS_API_SECRET=xxx          # Censys
export HIBP_API_KEY=xxx               # Have I Been Pwned
export SECURITYTRAILS_API_KEY=xxx     # SecurityTrails
export TWITTER_AUTH_TOKEN=xxx         # Twitter enhanced
export TWITTER_CT0=xxx                # Twitter enhanced
```

## Adding New Modules

```python
from social_recon.modules.base import BaseModule, ModuleResult, Finding, ModuleCategory

class MyModule(BaseModule):
    name = "my_module"
    category = ModuleCategory.SOCIAL
    description = "My custom OSINT module"
    supported_input_types = ["username", "email"]

    async def run(self, target, target_type, context=None):
        findings = []
        # Your OSINT logic here
        return ModuleResult(module_name=self.name, success=True, findings=findings)
```

## Legal Notice

Only public data is collected. No login, no cookies, no private access. This tool is for authorized security research and OSINT investigations only.

## Author

**Erfix404** — [github.com/Erfix404](https://github.com/Erfix404)
