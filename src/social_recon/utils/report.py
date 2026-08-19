"""Report generator — produces JSON, Markdown, and HTML reports."""
import json
import time
from pathlib import Path
from collections import Counter


def generate_report(output_dir: str | Path, pipeline_result: dict) -> dict[str, str]:
    """Generate all report formats. Returns dict of format -> filepath."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = {}

    # Load raw results
    results_file = output_dir / "recon_results.json"
    if results_file.exists():
        data = json.loads(results_file.read_text(encoding="utf-8"))
    else:
        data = pipeline_result

    # 1. JSON report (already saved by pipeline)
    reports["json"] = str(results_file)

    # 2. Markdown report
    md_path = output_dir / "report.md"
    md_content = _generate_markdown(data)
    md_path.write_text(md_content, encoding="utf-8")
    reports["markdown"] = str(md_path)

    # 3. HTML report
    html_path = output_dir / "report.html"
    html_content = _generate_html(data)
    html_path.write_text(html_content, encoding="utf-8")
    reports["html"] = str(html_path)

    print(f"  [+] Reports generated: {', '.join(reports.keys())}")
    return reports


def _generate_markdown(data: dict) -> str:
    """Generate Markdown report."""
    target = data.get("target", "unknown")
    target_type = data.get("target_type", "unknown")
    mode = data.get("mode", "full")
    findings = data.get("findings", [])
    context = data.get("context", {})

    lines = [
        f"# 🔭 گزارش OSINT — {target}",
        f"",
        f"**نوع ورودی:** {target_type} | **حالت اسکن:** {mode} | **تعداد یافته‌ها:** {len(findings)}",
        "",
    ]

    # Group findings by type
    by_type = {}
    for f in findings:
        dt = f.get("data_type", "unknown")
        by_type.setdefault(dt, []).append(f)

    # Profiles
    profiles = by_type.get("profile", [])
    if profiles:
        lines.append("## 🌐 پروفایل‌ها و حساب‌ها")
        for p in profiles:
            val = p.get("value", {})
            if isinstance(val, dict):
                platform = val.get("platform", val.get("site", ""))
                url = val.get("url", "")
                extras = []
                if val.get("title"):
                    extras.append(f"عنوان: {val['title']}")
                if val.get("members"):
                    extras.append(f"اعضا: {val['members']}")
                if val.get("followers"):
                    extras.append(f"فالوور: {val['followers']}")
                extra_str = " — " + " | ".join(extras) if extras else ""
                lines.append(f"- **{platform}**: [{url}]({url}){extra_str}")
        lines.append("")

    # Emails
    emails = context.get("emails", [])
    if emails:
        lines.append("## 📧 ایمیل‌های یافت شده")
        for e in emails:
            lines.append(f"- `{e}`")
        lines.append("")

    # Phones
    phones = context.get("phones", [])
    if phones:
        lines.append("## 📞 شماره تلفن‌ها")
        for p in phones:
            lines.append(f"- `{p}`")
        lines.append("")

    # Phone info
    phone_infos = by_type.get("phone_info", [])
    if phone_infos:
        lines.append("## 📱 اطلاعات تلفن")
        for pi in phone_infos:
            val = pi.get("value", {})
            if isinstance(val, dict):
                if val.get("operator_name"):
                    lines.append(f"- اپراتور: **{val['operator_name']}** ({val.get('operator_code', '')})")
                if val.get("phone"):
                    lines.append(f"- شماره: `{val['phone']}`")
        lines.append("")

    # Breaches
    breaches = by_type.get("breach", [])
    breach_risks = by_type.get("breach_risk", [])
    if breaches or breach_risks:
        lines.append("## 🔓 نقض داده‌ها")
        for b in breaches:
            val = b.get("value", {})
            if isinstance(val, dict):
                lines.append(f"- **{val.get('breach_name', val.get('source', ''))}**: {val.get('date', '')} — {val.get('pwn_count', '')} رکورد")
        for br in breach_risks:
            val = br.get("value", {})
            if isinstance(val, dict):
                lines.append(f"- ⚠️ خطر: **{val.get('breach', '')}** ({val.get('year', '')}) — {val.get('description', '')[:80]}")
        lines.append("")

    # Search hits
    hits = by_type.get("search_hit", [])
    if hits:
        lines.append("## 🔍 نتایج جستجو")
        for h in hits[:20]:
            val = h.get("value", {})
            if isinstance(val, dict):
                url = val.get("url", "")
                snippet = val.get("snippet", "")[:100]
                lines.append(f"- [{url[:60]}]({url}): {snippet}")
        lines.append("")

    # Subdomains
    subs = by_type.get("subdomain", [])
    if subs:
        lines.append("## 🌐 ساب‌دومین‌ها")
        seen = set()
        for s in subs:
            val = s.get("value", {})
            domain = val.get("domain", "") if isinstance(val, dict) else ""
            if domain and domain not in seen:
                seen.add(domain)
                lines.append(f"- `{domain}`")
        lines.append("")

    # Images
    images = by_type.get("image", [])
    if images:
        lines.append("## 🖼 تصاویر")
        for img in images:
            val = img.get("value", {})
            if isinstance(val, dict):
                lines.append(f"- **{val.get('source', '')}**: {val.get('path', '')} ({val.get('size', 0)} bytes)")
        lines.append("")

    # Secrets
    secrets = by_type.get("secret", [])
    if secrets:
        lines.append("## 🔐 اسرار و اطلاعات حساس")
        for s in secrets:
            val = s.get("value", {})
            if isinstance(val, dict):
                stype = val.get("type", "")
                src = val.get("source", "")
                v = val.get("value", "")[:40]
                lines.append(f"- **{stype}**: `{v}` (از: {src})")
        lines.append("")

    # Email reputation
    rep = by_type.get("email_reputation", [])
    if rep:
        lines.append("## 🛡️ اعتبار ایمیل")
        for r in rep:
            val = r.get("value", {})
            if isinstance(val, dict):
                lines.append(f"- **{val.get('email', '')}**: اعتبار={val.get('reputation', '')}، مشکوک={val.get('suspicious', '')}")
        lines.append("")

    # Summary
    lines.append("---")
    total_profiles = len(profiles)
    lines.append(f"**📊 خلاصه:** {total_profiles} پروفایل | {len(emails)} ایمیل | {len(phones)} تلفن | {len(findings)} یافته کل")
    lines.append("")
    lines.append("*گزارش خودکار توسط Social-Recon v2.0 تولید شد. فقط داده‌های عمومی.*")

    return "\n".join(lines)


def _generate_html(data: dict) -> str:
    """Generate interactive HTML report."""
    target = data.get("target", "unknown")
    target_type = data.get("target_type", "unknown")
    mode = data.get("mode", "full")
    findings = data.get("findings", [])
    context = data.get("context", {})
    modules = data.get("modules", {})
    duration = data.get("duration", 0)

    # Stats
    by_type = Counter(f.get("data_type", "unknown") for f in findings)
    profiles_count = by_type.get("profile", 0)
    emails_count = len(context.get("emails", []))
    phones_count = len(context.get("phones", []))
    successful_modules = sum(1 for m in modules.values() if m.get("success"))

    # Chart data — findings by type
    type_labels = json.dumps(list(by_type.keys()))
    type_values = json.dumps(list(by_type.values()))

    # Chart data — modules by duration
    mod_names = json.dumps([n[:15] for n in modules.keys()])
    mod_durations = json.dumps([round(m.get("duration", 0), 1) for m in modules.values()])
    mod_success = json.dumps([1 if m.get("success") else 0 for m in modules.values()])

    # Profile rows
    profiles_html = ""
    for f in findings:
        if f.get("data_type") != "profile":
            continue
        val = f.get("value", {})
        if not isinstance(val, dict):
            continue
        platform = val.get("platform", "")
        url = val.get("url", "#")
        title = val.get("title", val.get("name", val.get("username", "")))
        confidence = f.get("confidence", 0)
        conf_color = "#4caf50" if confidence >= 0.7 else "#ff9800" if confidence >= 0.4 else "#f44336"
        profiles_html += f"""
        <tr>
            <td><strong>{platform}</strong></td>
            <td><a href="{url}" target="_blank">{title or url[:50]}</a></td>
            <td><span style="color:{conf_color}">{confidence:.0%}</span></td>
            <td>{f.get("source", "")}</td>
        </tr>"""

    # Emails
    emails_html = "".join(f"<li><code>{e}</code></li>" for e in context.get("emails", []))
    phones_html = "".join(f"<li><code>{p}</code></li>" for p in context.get("phones", []))

    # Module status
    modules_html = ""
    for name, info in modules.items():
        status = "✅" if info.get("success") else "❌"
        findings_c = info.get("findings_count", 0)
        dur = info.get("duration", 0)
        modules_html += f"<tr><td>{name}</td><td>{status}</td><td>{findings_c}</td><td>{dur:.1f}s</td></tr>"

    # Secrets HTML
    secrets = [f for f in findings if f.get("data_type") == "secret"]
    secrets_html = ""
    for s in secrets[:20]:
        val = s.get("value", {})
        if isinstance(val, dict):
            stype = val.get("type", "")
            v = val.get("value", "")[:50]
            src = val.get("source", "")[:30]
            conf = s.get("confidence", 0)
            conf_color = "#f44336" if conf >= 0.8 else "#ff9800" if conf >= 0.5 else "#8b949e"
            secrets_html += f'<tr><td>{stype}</td><td><code>{v}</code></td><td>{src}</td><td style="color:{conf_color}">{conf:.0%}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>گزارش OSINT — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #58a6ff; margin-bottom: 10px; font-size: 28px; }}
h2 {{ color: #79c0ff; margin: 30px 0 15px; font-size: 20px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
.header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }}
.stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
.stat-num {{ font-size: 32px; font-weight: bold; color: #58a6ff; }}
.stat-label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }}
.chart-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
.chart-box canvas {{ max-height: 280px; }}
table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
th {{ background: #21262d; color: #79c0ff; padding: 12px; text-align: right; font-size: 13px; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }}
tr:hover {{ background: #1c2128; }}
a {{ color: #58a6ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
ul {{ padding-right: 20px; }}
li {{ margin: 6px 0; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; }}
.badge-green {{ background: #1b4332; color: #4caf50; }}
.badge-red {{ background: #3d1f1f; color: #f44336; }}
.section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
.footer {{ text-align: center; color: #484f58; margin-top: 40px; font-size: 12px; }}
@media (max-width: 768px) {{ .charts {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>🔭 گزارش OSINT — {target}</h1>
    <p style="color:#8b949e;margin-top:8px">نوع: {target_type} | حالت: {mode} | زمان: {duration:.1f} ثانیه | ماژول‌ها: {successful_modules}/{len(modules)}</p>
</div>

<div class="stats">
    <div class="stat"><div class="stat-num">{profiles_count}</div><div class="stat-label">پروفایل</div></div>
    <div class="stat"><div class="stat-num">{emails_count}</div><div class="stat-label">ایمیل</div></div>
    <div class="stat"><div class="stat-num">{phones_count}</div><div class="stat-label">تلفن</div></div>
    <div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-label">یافته کل</div></div>
    <div class="stat"><div class="stat-num">{len(modules)}</div><div class="stat-label">ماژول</div></div>
</div>

{f'<h2>📧 ایمیل‌ها</h2><div class="section"><ul>{emails_html}</ul></div>' if emails_html else ''}

{f'<h2>📞 تلفن‌ها</h2><div class="section"><ul>{phones_html}</ul></div>' if phones_html else ''}

<h2>📊 نمودار تحلیلی</h2>
<div class="charts">
    <div class="chart-box">
        <canvas id="typeChart"></canvas>
    </div>
    <div class="chart-box">
        <canvas id="moduleChart"></canvas>
    </div>
</div>

<h2>🌐 پروفایل‌ها</h2>
<div class="section">
<table>
    <tr><th>پلتفرم</th><th>لینک</th><th>اعتماد</th><th>منبع</th></tr>
    {profiles_html if profiles_html else '<tr><td colspan="4" style="text-align:center">پروفایلی یافت نشد</td></tr>'}
</table>
</div>

<h2>⚙️ ماژول‌ها</h2>
<div class="section">
<table>
    <tr><th>ماژول</th><th>وضعیت</th><th>یافته‌ها</th><th>زمان</th></tr>
    {modules_html}
</table>
</div>

{f"""<h2>🔐 اسرار و اطلاعات حساس</h2>
<div class="section">
<table>
    <tr><th>نوع</th><th>مقدار</th><th>منبع</th><th>اعتماد</th></tr>
    {secrets_html}
</table>
</div>""" if secrets_html else ''}

<div class="footer">
    <p>Social-Recon v2.0 — فقط داده‌های عمومی — تولید شده در {time.strftime('%Y-%m-%d %H:%M')}</p>
</div>

<script>
const chartColors = ['#58a6ff','#f97583','#56d364','#e3b341','#bc8cff','#79c0ff','#ff7b72','#7ee787','#d2a8ff','#ffa657','#a5d6ff','#ffdf5d'];

// Findings by type — doughnut chart
new Chart(document.getElementById('typeChart'), {{
    type: 'doughnut',
    data: {{
        labels: {type_labels},
        datasets: [{{ data: {type_values}, backgroundColor: chartColors, borderColor: '#0d1117', borderWidth: 2 }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            title: {{ display: true, text: 'یافته‌ها بر اساس نوع', color: '#c9d1d9', font: {{ size: 14 }} }},
            legend: {{ position: 'bottom', labels: {{ color: '#8b949e', font: {{ size: 11 }} }} }}
        }}
    }}
}});

// Modules by duration — bar chart
new Chart(document.getElementById('moduleChart'), {{
    type: 'bar',
    data: {{
        labels: {mod_names},
        datasets: [{{
            label: 'زمان (ثانیه)',
            data: {mod_durations},
            backgroundColor: {mod_success}.map(s => s ? '#56d364' : '#f97583'),
            borderColor: '#30363d',
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        indexAxis: 'y',
        plugins: {{
            title: {{ display: true, text: 'زمان اجرای ماژول‌ها', color: '#c9d1d9', font: {{ size: 14 }} }},
            legend: {{ display: false }}
        }},
        scales: {{
            x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
            y: {{ ticks: {{ color: '#8b949e', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
        }}
    }}
}});
</script>

</div>
</body>
</html>"""
