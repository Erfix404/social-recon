---
name: social-recon
description: "Use when the user wants to perform OSINT reconnaissance on a username, email, or phone number — extracting all public data across global and Persian platforms."
tags: [recon, osint, social, telegram]
model: gpt-4o-mini
---

# Social Recon Skill

This skill enables automated, comprehensive OSINT scanning using publicly available data sources.

## Supported Input Types
- Username (e.g., `amirezamky9` or `@amirezamky9`)
- Email address
- Phone number
- Domain name

## Platforms Covered
### International
- Twitter, Instagram, GitHub, Reddit, TikTok, Medium, YouTube
- HaveIBeenPwned, Hunter.io, Clearbit
- Shodan, Censys, ZoomEye

### Persian / Iran-Focused
- Aparat, Filimo, Okala, Hamijar, Jobinja, Zoomg, Snapp, Divar
- Telegram public channels and bots

## Usage
```bash
./run.sh <username_or_identifier>
```

## Output
- report.md (human-readable)
- report.json (structured)
- screenshots/ (where applicable)

## Privacy Note
Only public data is collected. No login, no cookies, no scraping behind authentication.