# Social-Recon v2.0 — OSINT Reconnaissance Framework

Advanced social media reconnaissance tool with **exceptional Iranian platform coverage**. Extracts public data from usernames, emails, and phone numbers across global and Persian platforms.

## What Makes This Different

- **25+ Iranian platforms** — Aparat, Virgool, Jobinja, Quera, Digikala, Eitaa, Bale, Rubika and more. Maigret (3000+ sites) has ZERO Iranian coverage.
- **Iranian breach database** — Checks against Digikala, Aparat, Snapp breaches that HIBP doesn't track.
- **Phone operator identification** — Instantly identify همراه اول، ایرانسل، رایتل from prefix.
- **Async pipeline** — Modules run concurrently for maximum speed.
- **Plugin architecture** — Easy to add new modules.
- **Intelligent chaining** — Found email feeds into phone search, which feeds into social lookup.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a scan
python run.py <username|email|phone> [light|full|hawk]

# Examples
python run.py erfix404              # Full scan on username
python run.py user@email.com hawk   # Maximum recon on email
python run.py 09123456789 light     # Quick phone lookup
```

## Scan Modes

| Mode | Description | Time |
|------|-------------|------|
| `light` | Fast scan — username/email basic lookup | ~30s |
| `full` | All passive modules including 25+ Iranian platforms | ~2-5min |
| `hawk` | Maximum recon — breach checks, CT logs, dorking, all platforms | ~5-10min |

## Modules

### Iranian Platforms (Our Advantage)
- **25+ platforms**: Aparat, Virgool, Jobinja, Quera, Hamijar, Karboom, IranTalent, Digikala, Basalam, Torob, Eitaa, Rubika, iGap, Bale, CafeBazaar, Myket, SnappFood, MrBilit, Alibaba.ir, Zoomit, Zoomg, Filimo, and more
- **Aparat deep recon**: Profile, videos, followers via public API
- **Phone operator ID**: همراه اول، ایرانسل، رایتل، تالیا، شاتل موبایل

### Global Platforms
- **Username enumeration**: Maigret integration (3000+ sites)
- **GitHub**: Profile, events, commit emails, repo secrets
- **Telegram**: t.me scraping, channel search
- **Instagram/X**: Profile and content analysis

### Enrichment
- **Email enrichment**: Gravatar, EmailRep, GitHub commit search, social probing
- **Phone intelligence**: Operator ID, OSINT dorks, social link discovery
- **Breach checking**: HIBP + Iranian breach databases
- **Certificate Transparency**: crt.sh, CertSpotter for subdomain discovery

### Infrastructure
- **DNS/WHOIS**: Domain intelligence
- **Network recon**: Shodan, Censys integration
- **Secret scanning**: API keys, tokens in public code

## Output

```
output/<target>/
├── recon_results.json      # All findings (structured JSON)
├── report.md               # Human-readable report
└── images/                 # Downloaded profile images
```

## Project Structure

```
social-recon/
├── run.py                    # Entry point
├── src/social_recon/
│   ├── core/
│   │   ├── config.py         # Centralized configuration
│   │   ├── pipeline.py       # Async pipeline orchestrator
│   │   └── input_classifier.py
│   ├── modules/
│   │   ├── base.py           # Module base class
│   │   ├── iranian_platforms.py   # 25+ Iranian platforms
│   │   ├── breach_checker.py      # HIBP + Iranian breaches
│   │   ├── phone_intel.py         # Phone number intelligence
│   │   ├── email_enricher.py      # Email enrichment
│   │   └── cert_transparency.py   # CT log mining
│   └── utils/
├── scripts/                  # Legacy scripts (v1)
├── requirements.txt
└── setup.py
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

## Environment Variables

```bash
# Optional API keys for enhanced functionality
export SHODAN_API_KEY="..."
export HIBP_API_KEY="..."
export HUNTER_API_KEY="..."
export TELEGRAM_API_ID="..."
export TELEGRAM_API_HASH="..."
export VIRUSTOTAL_API_KEY="..."
export SECURITYTRAILS_API_KEY="..."

# Optional proxy
export SOCIAL_RECON_PROXY="socks5://127.0.0.1:9050"  # Tor
```

## Legal Notice

Only public data is collected. No login, no cookies, no private access. This tool is for authorized security research and OSINT investigations only.

## License

MIT
