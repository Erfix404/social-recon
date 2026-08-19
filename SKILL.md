---
name: social-recon
description: "Advanced OSINT reconnaissance — extract public data from usernames, emails, and phone numbers across 30+ global and 25+ Persian platforms."
tags: [recon, osint, social, telegram, iranian, security]
---

# Social-Recon v2.0

Async OSINT framework with exceptional Iranian platform coverage.

## Supported Input Types
- Username (e.g., `erfix404` or `@erfix404`)
- Email address (e.g., `user@example.com`)
- Phone number (e.g., `09123456789`)
- Domain name (e.g., `example.com`)

## Usage
```bash
python run.py <target> [light|full|hawk]
```

## Modes
- **light**: Fast username/email lookup (~30s)
- **full**: All passive modules + Iranian platforms (~2-5min)
- **hawk**: Maximum recon including breach checks, CT logs (~5-10min)

## Unique Capabilities
- 25+ Iranian platforms (Aparat, Virgool, Jobinja, Digikala, Eitaa, Bale, Rubika...)
- Iranian breach database checking
- Iranian phone operator identification
- Certificate Transparency subdomain discovery
- Email enrichment (Gravatar, GitHub commits, EmailRep)
