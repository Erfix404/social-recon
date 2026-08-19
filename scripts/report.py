#!/usr/bin/env python3
"""Report generator — produces report.md from all collected JSON outputs."""
import os, sys, json

OUT_DIR = sys.argv[1]
TARGET = os.path.basename(os.path.normpath(OUT_DIR))

def load(name):
    p = os.path.join(OUT_DIR, name)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def load_nested(name, subkey=None):
    d = load(name)
    if d and subkey:
        return d.get(subkey, d)
    return d or {}

deep = load("deep_recon.json") or {}
tg = load("telegram.json")

print(f"# 🔭 گزارش کامل استاک کردن — {TARGET}")
print()

# --- Identity ---
real_names = deep.get("social_profiles", {}).get("Telegram", {}).get("fullname") or "ناشناس"
print(f"## 🧑 هویت یافت شده")
if real_names != "ناشناس":
    print(f"- نام: `{real_names}`")
else:
    print("- نام شخصیت یافت نشد.")
print()

# --- Telegram ---
print("## 📱 تلگرام")
if tg and tg.get("ok"):
    res = tg["result"]
    print(f"- آی‌دی: `{res.get('id')}`")
    print(f"- نوع: `{res.get('type')}`")
    print(f"- نام: `{res.get('title', res.get('username', '-'))}`")
else:
    print("- (از طریق Bot API پیدا نشد)")

tp = deep.get("telegram_profile", {})
if tp.get("title"):
    print(f"- نام نمایشی: `{tp.get('title')}`")
    print(f"- بیو: `{tp.get('description')}`")
print()

# --- Social Profiles ---
print("## 🌐 پروفایل‌های شبکه‌های اجتماعی")
sp = deep.get("social_profiles", {})
if sp:
    for site, info in sp.items():
        line = f"- [{site}]({info.get('url')}): ✅"
        extras = []
        if info.get("fullname"): extras.append(f"نام: {info['fullname']}")
        if info.get("bio"): extras.append(f"بیو: {info['bio'][:50]}")
        if info.get("follower_count") is not None: extras.append(f"فالوور: {info['follower_count']}")
        if info.get("private") is not None: extras.append(f"خصوصی: {info['private']}")
        if extras:
            line += " — " + " | ".join(extras)
        print(line)
else:
    print("- در Maigret یافت نشد.")
print()

# --- GitHub ---
print("## 🐙 GitHub / کد")
gp = deep.get("github_profile", {})
if gp.get("id"):
    print(f"- نام: `{gp.get('name')}`")
    print(f"- بیو: `{gp.get('bio')}`")
    print(f"- شرکت: `{gp.get('company')}`")
    print(f"- محل: `{gp.get('location')}`")
    print(f"- وب‌سایت: `{gp.get('blog')}`")
    print(f"- ایمیل عمومی: `{gp.get('email')}`")
    print(f"- ریپوها: {gp.get('public_repos')} | فالوور: {gp.get('followers')} | فالوویینگ: {gp.get('following')}")
    print(f"- تاریخ عضویت: `{gp.get('created_at')}`")
    if deep.get("github_events"):
        print("- فعالیت‌های اخیر:")
        for e in deep["github_events"][:10]:
            print(f"  - {e.get('type')} در `{e.get('repo')}` ({e.get('created', '')[:10]})")
else:
    print("- حساب یافت نشد یا محدودیت API.")
print()

# --- Emails ---
print("## 📧 ایمیل‌های یافت شده")
emails = deep.get("emails", [])
if emails:
    for em in emails:
        print(f"- `{em}`")
else:
    print("- ایمیل یافت نشد.")
print()

# --- Holehe ---
holehe = deep.get("holehe", {})
if holehe and not holehe.get("error") and holehe:
    print(f"## 📋 ردپای ایمیل `{deep.get('holehe_checked_email')}` (holehe)")
    for site in sorted(holehe.keys()):
        print(f"- {site}: ✅ حساب دارد")
    print()
elif holehe:
    print(f"## 📋 holehe: {holehe.get('error', 'خطا ناشناخته')}")
    if holehe.get("raw_tail"):
        print(f"```\n{holehe.get('raw_tail', '')[-300:]}\n```")
    print()

# --- EmailRep ---
er = deep.get("emailrep", {})
if er:
    print("## 🛡️ EmailRep.io")
    print(f"- Reputation: `{er.get('reputation')}` | Suspicious: `{er.get('suspicious')}` | References: `{er.get('references')}`")
    det = er.get("details", {})
    if det:
        for k, v in det.items():
            if isinstance(v, (str, int, float, bool)) and v and v is not True:
                print(f"  - {k}: `{v}`")
    print()

# --- Phones ---
print("## 📞 شماره موبایل")
phones = deep.get("phones", [])
hits = deep.get("search_hits", [])
if phones:
    for ph in phones:
        print(f"- `{ph}`")
elif hits:
    print("- شماره‌ای یافت نشد — اما نتایج جستجو:")
    for h in hits[:15]:
        print(f"  - [{h.get('query')}]({h.get('url')}): {h.get('snippet', '')[:100]}")
else:
    print("- شماره موبایل یافت نشد.")
print()

# --- Images ---
print("## 🖼 تصاویر یافت شده")
imgs = deep.get("images", [])
if imgs:
    for im in imgs:
        print(f"- **{im.get('name')}**: {im.get('path')} ({im.get('size')} bytes, md5: {im.get('md5')})")
else:
    print("- تصویری یافت نشد.")
print()

# --- Persian Platforms ---
print("## 🇮🇷 پلتفرم‌های فارسی")
pf = deep.get("persian_platforms", {})
hits = [(k, v) for k, v in pf.items() if v.get("exists")]
if hits:
    for k, v in hits:
        print(f"- [{k}]({v.get('url')}): ✅ ({v.get('status')})")
else:
    print("- پلتفرم فارسی یافت نشد.")
print()

# --- Deep Web / Archive ---
print("## 🌐 وب عمیق و ارشیو")
dw = load("deep_web_results.json")
if dw:
    wb = dw.get("wayback_urls", [])
    cc = dw.get("commoncrawl_hits", [])
    sh = dw.get("search_hits", [])
    if wb:
        print(f"- **Wayback Machine**: {len(wb)} اسنپ‌شات")
        for u in wb[:5]:
            print(f"  - [{u.get('timestamp', '')[:8]}]({u.get('url', '')})")
    if cc:
        print(f"- **Common Crawl**: {len(cc)} ردیف")
    if sh:
        print(f"- **جستجوهای وب**: {len(sh)} نتیجه")
        for h in sh[:6]:
            print(f"  - [{h.get('url', '')[:60]}]({h.get('url', '')}): {h.get('snippet', '')[:80]}")
    if not (wb or cc or sh):
        print("- نتیجه‌ای یافت نشد.")
print()

# --- GitHub Code Search ---
print("## 🔍 جستجو در کدهای گیت‌هاب")
gs = load("github_code_search_results.json")
if gs:
    cm = gs.get("code_matches", [])
    if cm:
        print(f"- {len(cm)} نتیجه یافت شد:")
        for c in cm[:6]:
            if "total_count" in c:
                print(f"  - `{c['query']}`: {c['total_count']} مورد")
            else:
                print(f"  - [{c.get('repo', '')}]({c.get('url', '')})")
    else:
        print("- نیاز به لاگین گیت‌هاب یا نتیجه‌ای یافت نشد.")
    if gs.get("repos_list") and isinstance(gs["repos_list"], list):
        print(f"\n**ریپوهای عمومی ({len(gs['repos_list'])}):**")
        for r in gs["repos_list"][:10]:
            print(f"- [{r['name']}]({r['url']}) ({r.get('language', '')})")
    if gs.get("gists") and isinstance(gs["gists"], list):
        print(f"\n**گیست‌ها ({len(gs['gists'])}):**")
        for g in gs["gists"][:5]:
            print(f"- [{g.get('id', '')[:16]}]({g.get('url', '')})")
    if gs.get("emails_found"):
        print(f"\n**ایمیل‌های یافت شده در کدها:**")
        for em in gs["emails_found"]:
            print(f"- `{em}`")
print()

# --- Telegram Channels ---
print("## 💬 جستجو در کانال‌های تلگرامی")
tgcs = load("tg_channel_search_results.json")
if tgcs:
    channels = tgcs.get("channels_found", [])
    mentions = tgcs.get("mentions_found", [])
    if channels:
        print(f"- **کانال‌های یافت شده ({len(channels)}):**")
        for ch in channels[:10]:
            print(f"  - @{ch.get('username', '')} (از: {ch.get('source', '')})")
    if mentions:
        print(f"\n- **منشاها یافت شده ({len(mentions)}):**")
        for m in mentions[:10]:
            loc = f"کانال: {m.get('channel')}" if m.get("channel") else f"جستجو: {m.get('query')}"
            print(f"  - {loc}: `{m.get('context', '')[:120]}`")
    if not (channels or mentions):
        print("- منشار یا پیامی یافت نشد.")
print()

# --- Leak Check ---
print("## 📋 بررسی دیتابیس‌های فاش‌شده")
lc = load("leak_check_results.json")
if lc:
    hibp = lc.get("hibp_breaches", [])
    deh = lc.get("dehashed", {})
    lsh = lc.get("leak_search_hits", [])
    if hibp:
        print(f"- **HaveIBeenPwned**: {len(hibp)} دیتابیس")
        for b in hibp[:10]:
            print(f"  - `{b}`")
    if deh and isinstance(deh, dict):
        if deh.get("found"):
            print(f"- **Dehashed**: یافت شد ({deh.get('count', '?')} مورد)")
        else:
            print(f"- **Dehashed**: {deh.get('note', 'اطلاعات کامل نیاز به لاگین')}")
    if lsh:
        print(f"- **جستجوهای لیک**: {len(lsh)} نتیجه")
        for h in lsh[:5]:
            print(f"  - [{h.get('url', '')[:60]}]({h.get('url', '')}): {h.get('snippet', '')[:80]}")
print()

# --- Persian Search ---
print("## 🇮🇷 OSINT.ir + جستجوهای فارسی")
oir = load("osint_ir_results.json")
if oir:
    found_ones = [r for r in oir.get("osint_ir_results", []) if r.get("target_found")]
    if found_ones:
        print(f"- **پلتفرم‌های یافت شده ({len(found_ones)}):**")
        for r in found_ones[:10]:
            print(f"  - [{r.get('resource')}] ({r.get('status_code')}) — {r.get('title', '')[:60]}")
    else:
        print("- در منابع کلیدی یافت نشد.")
    pd = oir.get("persian_dorks", [])
    if pd:
        print(f"\n- **دورک‌های فارسی ({len(pd)}):**")
        for p in pd[:6]:
            print(f"  - [{p.get('url', '')[:60]}]({p.get('url', '')}): {p.get('snippet', '')[:80]}")
print()

print("---")
print(f"**📊 خلاصه نهایی:** استخراج شده از {len(deep.get('social_profiles', {}))} شبکه + {len(emails)} ایمیل + {len(deep.get('images', []))} تصویر")
print("*گزارش به‌صورت خودکار توسط social-recon تولید شد. فقط داده‌های عمومی.*")