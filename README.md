# 🌐 Social Recon — OSINT Eagle-Eye Skill

A high-efficiency OSINT reconnaissance tool that extracts public data from usernames, emails, and phone numbers across **global and Persian platforms**.

Designed for security researchers, investigators, and developers.

## 🧰 Features

- ✅ Username scan via Maigret (3000+ platforms) and Sherlock
- ✅ GitHub profile + commit history + avatar
- ✅ Telegram profile via Bot API + t.me scraping
- ✅ Email footprint via Holehe and EmailRep
- ✅ Phone number discovery via dorks
- ✅ Persian platforms: Aparat, Filimo, Digikala, Hamijar, Jobinja, Quera, Virgool
- ✅ Image extraction from identified profiles
- ✅ Reports in: `report.md`, `deep_recon.json`

## 🚀 Usage

```bash
./run.sh <username|email|phone>
```

Example:

```bash
./run.sh amirezamky9
```

## 📦 Output

```
output/amirezamky9/
├── deep_recon.json     # Full JSON data
├── report.md           # Human-readable report
├── maigret.json        # Raw Maigret results
├── telegram.json       # Telegram Bot API response
└── images/
    ├── instagram.jpg
    ├── github.png
    └── telegram.jpg
```

## ⚠️ Legal Notice

Only public data is collected. No login, no cookies, no private access.
