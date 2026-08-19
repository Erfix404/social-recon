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

deep = load("deep_recon.json") or {}
ig = load("instagram_results.json") or {}
tw = load("twitter_results.json") or {}
pi = load("phoneinfoga_results.json") or {}
infra = load("infrastructure_results.json") or {}
tg = load("telegram.json")
gs = load("github_code_search_results.json") or {}
tgcs = load("tg_channel_search_results.json") or {}
lc = load("leak_check_results.json") or {}
oir = load("osint_ir_results.json") or {}
dw = load("deep_web_results.json") or {}

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

# --- Social Profiles (Maigret) ---
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

# --- Instagram ---
print("## 📷 اینستاگرام (Instaloader/snscrape)")
if ig.get("exists"):
    print(f"- پروفایل یافت شد: https://www.instagram.com/{ig.get('username')}/")
    prof = ig.get("profile", {})
    if prof:
        print(f"- بیو: `{prof.get('bio', '')[:200]}`")
        print(f"- تعداد فالوور: {prof.get('followers_count', 'N/A')}")
        print(f"- تعداد پست: {prof.get('tweet_count', 'N/A')}")
    print(f"- پست‌های اخیر: {len(ig.get('recent_posts', []))}")
    for post in ig.get("recent_posts", [])[:3]:
        print(f"  - [{post.get('url', '')[:70]}]({post.get('url', '')}): {post.get('content', '')[:80]}...")
else:
    if ig.get("errors"):
        print(f"- خطا: {ig['errors'][0][:100]}")
    else:
        print("- حساب یافت نشد یا محدودیت دسترسی.")
print()

# --- Twitter/X ---
print("## 🐦 توییتر/X (snscrape)")
if tw.get("exists"):
    print(f"- حساب یافت شد: https://twitter.com/{tw.get('username')}")
    prof = tw.get("profile", {})
    if prof:
        print(f"- توضیحات: `{prof.get('description', '')[:200]}`")
        print(f"- فالوور: {prof.get('followers_count', 'N/A')} | فالوویینگ: {prof.get('following_count', 'N/A')}")
        print(f"- تعداد توییت: {prof.get('tweet_count', 'N/A')}")
        if prof.get("verified"):
            print(f"- ✅ حساب تأیید شده")
        if prof.get("location"):
            print(f"- مکان: `{prof.get('location')}`")
    print(f"- منشاها (تاکید): {len(tw.get('mentions', []))}")
    print(f"- نتایج جستجو: {len(tw.get('search_results', []))}")
else:
    if tw.get("errors"):
        print(f"- خطا: {tw['errors'][0][:100]}")
    else:
        print("- حساب یافت نشد یا محدودیت دسترسی.")
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
if phones:
    for ph in phones:
        print(f"- `{ph}`")

# --- PhoneInfoga ---
if pi.get("phoneinfoga"):
    print("\n## 📱 PhoneInfoga — تحلیل شماره تلفن")
    pig = pi.get("phoneinfoga", {})
    if isinstance(pig, dict):
        if "country" in pig:
            print(f"- کشور: `{pig.get('country')}`")
        if "location" in pig:
            print(f"- مکان: `{pig.get('location')}`")
        if "carrier" in pig:
            print(f"- اپراتور: `{pig.get('carrier')}`")
        if "line_type" in pig:
            print(f"- نوع خط: `{pig.get('line_type')}`")
        if "input" in pig:
            print(f"- فرمت ورودی: `{pig.get('input')}`")
        if "international" in pig:
            print(f"- بین‌المللی: `{pig.get('international')}`")
        if "e164" in pig:
            print(f"- E.164: `{pig.get('e164')}`")
        if "rfc3966" in pig:
            print(f"- RFC3966: `{pig.get('rfc3966')}`")
        if pig.get("country") == "IR":
            print("  - ⚠️ شماره ایرانی — بررسی سایت‌های محلی انجام شد.")
    pi_hits = pi.get("search_hits", [])
    if pi_hits:
        print(f"\n- نتایج وب‌جستجو: {len(pi_hits)}")
        for h in pi_hits[:3]:
            print(f"  - [{h.get('url', '')[:60]}]({h.get('url', '')}): {h.get('snippet', '')[:80]}")
    print()

hits = deep.get("search_hits", [])
if phones:
    if hits:
        print("\n- نتایج جستجو برای شماره:")
        for h in hits[:15]:
            print(f"  - [{h.get('query')}]({h.get('url')}): {h.get('snippet', '')[:100]}")
else:
    print("\n- شماره موبایل یافت نشد.")
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

# --- Infrastructure Recon ---
print("## 🌐 Infrastructure Recon (DNS/ASN/Cloud)")
if infra:
    dns = infra.get("dns", {})
    if dns:
        print(f"- **رکوردهای DNS ({len(dns)}):**")
        for k, v in list(dns.items())[:8]:
            print(f"  - {k}: `{v[:100]}`")
    subdomains = infra.get("subdomains", [])
    if subdomains:
        unique_subs = []
        seen = set()
        for s in subdomains:
            d = s.get("domain", "")
            if d not in seen:
                seen.add(d)
                unique_subs.append(d)
        print(f"\n- **ساب‌دومین‌های یافت شده ({len(unique_subs)}):**")
        for s in unique_subs[:15]:
            print(f"  - `{s}`")
    ports = infra.get("open_ports", [])
    if ports:
        print(f"\n- **پورت‌های باز:** `{', '.join(map(str, ports[:15]))}`")
    whois = infra.get("whois", {})
    if whois:
        print(f"\n- **WHOIS:**")
        if whois.get("registrar"):
            print(f"  - رجیسترار: `{whois.get('registrar')}`")
        if whois.get("creation_date"):
            print(f"  - تاریخ ایجاد: `{whois.get('creation_date')}`")
        if whois.get("expiration_date"):
            print(f"  - انقضا: `{whois.get('expiration_date')}`")
    asn = infra.get("asn", {})
    if asn:
        if isinstance(asn, dict) and "ip_api" in asn:
            ip_api = asn["ip_api"]
            print(f"\n- **اطلاعات ASN:**")
            print(f"  - کشور: `{ip_api.get('country')}`")
            print(f"  - منطقه: `{ip_api.get('regionName')}`")
            print(f"  - ISP: `{ip_api.get('isp')}`")
            print(f"  - ASN: `{ip_api.get('as')}`")
        elif isinstance(asn, dict) and "meta" in asn:
            print(f"\n- **اطلاعات ASN (BGPView):**")
            for key in ["asn", "description", "country", "ip_blocks"]:
                val = asn.get("meta", {}).get(key)
                if val:
                    print(f"  - {key}: `{val}`")
    ct = infra.get("cert_transparency", [])
    if ct:
        print(f"\n- **گواهی‌نامه شفافیت (crt.sh):** {len(ct)} گواهی")
    reverse = infra.get("reverse_ip", [])
    if reverse:
        print(f"\n- **Reverse IP:** {len(reverse)} دامنه")
        for d in reverse[:5]:
            print(f"  - `{d}`")
print()

# --- Deep Web / Archive ---
print("## 🌐 وب عمیق و ارشیو")
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

# --- Secret Scanner Results ---
print("## 🔐 اسکنر سرورها و اسرار (Secret Scanner)")
ss = load("secret_scan_results.json")
if ss:
    total = ss.get("total_secrets", len(ss.get("secrets", [])))
    if total:
        print(f"- **کل اسرار یافت شده: {total}**")
        persian = ss.get("persian_patterns_found", [])
        if persian:
            print(f"\n- **🚨 الگوهای خاص ایرانی ({len(persian)}):**")
            for p in persian[:10]:
                print(f"  - `{p['type']}`: `{p['value']}` (از: {p.get('source', '')[:40]})")
        generic = [s for s in ss.get("secrets", []) if s not in persian]
        if generic:
            print(f"\n- **اسرار عمومی ({len(generic)}):**")
            seen_types = set()
            for s in generic[:15]:
                if s["type"] not in seen_types:
                    seen_types.add(s["type"])
                    print(f"  - `{s['type']}`: `{s['value']}` (از: {s.get('source', '')[:40]})")
        if not persian and not generic:
            print("- هیچ سروری یافت نشد.")
    else:
        print("- هیچ سروری یافت نشد.")
    # Pastebin leaks
    pl = ss.get("pastebin_leaks", [])
    if pl:
        print(f"\n- **لیک‌های Paste سite‌ها ({len(pl)}):**")
        for p in pl[:5]:
            print(f"  - [{p.get('url', '')[:60]}]({p.get('url', '')}): {len(p.get('secrets_found', []))} سرور")
else:
    print("- بررسی سرورها انجام نشد.")
print()

# --- Network/Shodan Recon ---
print("## 🌐 شبکه و زیرساخت (Shodan/Censys/DNS)")
nr = load("network_recon_results.json")
if nr:
    shodan = nr.get("shodan", {})
    if shodan and shodan.get("ip"):
        print(f"- **Shodan:**")
        print(f"  - IP: `{shodan.get('ip')}`")
        print(f"  - ISP: `{shodan.get('isp')}` | کشور: `{shodan.get('country')}`")
        print(f"  - سازمان: `{shodan.get('org')}`")
        ports = shodan.get("ports", [])
        if ports:
            print(f"  - پورت‌ها: `{', '.join(map(str, ports[:15]))}`")
        vulns = shodan.get("vulns", [])
        if vulns:
            print(f"  - آسیب‌پذیری‌ها: {len(vulns)}")
            for v in vulns[:5]:
                print(f"    - `{v}`")
    else:
        print(f"- Shodan: {shodan.get('note', shodan.get('error', 'اطلاعاتی یافت نشد'))}")

    censys = nr.get("censys", {})
    if censys and censys.get("ip"):
        print(f"\n- **Censys:**")
        print(f"  - IP: `{censys.get('ip')}`")
        services = censys.get("services", [])
        for s in services[:5]:
            print(f"  - پورت {s.get('port')}: `{s.get('service_name', '')}` ({s.get('transport_protocol', '')})")
    else:
        if censys:
            print(f"\n- Censys: {censys.get('note', 'اطلاعاتی یافت نشد')}")

    cloud = nr.get("cloud_assets", [])
    if cloud:
        print(f"\n- **دارایی‌های ابری ({len(cloud)}):**")
        for c in cloud[:10]:
            print(f"  - `{c.get('type', '')}`: {c.get('name', '')} — {c.get('status', '')}")
    print()

# --- GitHub Advanced Results ---
print("## 🔍 GitHub Advanced Recon")
gadv = load("github_advanced_results.json") or gs
if gadv:
    repos = gadv.get("repos_list", gs.get("repos_list", []))
    repo_count = len(repos) if isinstance(repos, list) else 0
    if repo_count:
        print(f"- **ریپوهای عمومی ({repo_count}):**")
        for r in repos[:10]:
            print(f"  - [{r['name']}]({r['url']}) ({r.get('language', '')})")
        if gadv.get("description"):
            print(f"  - توضیحات: {r.get('description', '')[:100]}")

    secrets = gadv.get("repo_secrets", [])
    if not secrets:
        secrets = ss.get("github_secrets", []) if ss else []
    if secrets:
        print(f"\n- **اسرار یافت شده در ریپوها ({len(secrets)}):**")
        for s in secrets[:10]:
            print(f"  - `{s.get('type', '')}`: `{s.get('value', '')}` از `{s.get('repo', '')}`")

    gists = gadv.get("gists", gs.get("gists", []))
    if isinstance(gists, list) and gists:
        print(f"\n- **گیست‌ها ({len(gists)}):**")
        for g in gists[:5]:
            files = [f.get("name", "") for f in g.get("files", [])]
            print(f"  - [{g.get('id', '')[:16]}]({g.get('url', '')}): {', '.join(files[:3])}")

    commit_emails = gadv.get("commit_emails", [])
    if commit_emails:
        print(f"\n- **ایمیل‌های یافت شده در کامیت‌ها:**")
        for em in commit_emails[:5]:
            if em not in emails:
                print(f"  - `{em}`")

    orgs = gadv.get("org_members", [])
    if orgs:
        print(f"\n- **سازمان‌ها ({len(orgs)}):**")
        for o in orgs[:5]:
            print(f"  - [{o.get('org', '')}]({o.get('url', '')})")

    follower_graph = gadv.get("follower_graph", [])
    if follower_graph:
        print(f"\n- **کاربران مشابه یافت شده در گیت‌هاب ({len(follower_graph)}):**")
        for u in follower_graph[:5]:
            print(f"  - [{u.get('username', '')}]({u.get('url', '')})")

    issues = gadv.get("issues_prs", [])
    if issues:
        print(f"\n- **Issue/PRهای مرتبط ({len(issues)}):**")
        for i in issues[:5]:
            print(f"  - [{i.get('repo', '')}]({i.get('url', '')}): {i.get('title', '')[:60]}")
else:
    print("- اجرا نشده است.")
print()

# --- Deep Web / Archive ---
print("## 🌐 وب عمیق و ارشیو")
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
        print("- منشعر یا پیامی یافت نشد.")
print()

# --- Leak Check ---
print("## 📋 بررسی دیتابیس‌های فاش‌شده")
if lc:
    hibp = lc.get("hibp_breaches", [])
    lsh = lc.get("leak_search_hits", [])
    if hibp:
        print(f"- **HaveIBeenPwned**: {len(hibp)} دیتابیس")
        for b in hibp[:10]:
            print(f"  - `{b}`")
    if lsh:
        print(f"- **جستجوهای لیک**: {len(lsh)} نتیجه")
        for h in lsh[:5]:
            print(f"  - [{h.get('url', '')[:60]}]({h.get('url', '')}): {h.get('snippet', '')[:80]}")
else:
    print("- بررسی لیک انجام نشد.")
print()

# --- Persian Search ---
print("## 🇮🇷 OSINT.ir + جستجوهای فارسی")
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
total_profiles = len(deep.get('social_profiles', {})) + (1 if ig.get('exists') else 0) + (1 if tw.get('exists') else 0)
total_emails = len(emails)
total_images = len(deep.get('images', []))
print(f"**📊 خلاصه نهایی:** استخراج شده از {total_profiles} شبکه + {total_emails} ایمیل + {total_images} تصویر")
print("*گزارش به‌صورت خودکار توسط social-recon تولید شد. فقط داده‌های عمومی.*")