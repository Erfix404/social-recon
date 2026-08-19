#!/usr/bin/env python3
"""
Infrastructure Recon Pipeline — IP/ASN/DNS/whois/cert transparency.
Uses built-in tools and public APIs to map attack surface.

Tools used:
- DNS resolution (A, AAAA, MX, TXT, SPF, DMARC, DKIM)
- WHOIS lookup
- ASN mapping
- Certificate transparency (crt.sh)
- Reverse IP lookup
- Subdomain discovery (Certificate Transparency logs)
- Port scanning (top 100)
"""
import sys, json, os, re, time, socket, subprocess, requests
from urllib.parse import quote

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {
    "target": TARGET,
    "dns": {},
    "whois": {},
    "asn": {},
    "cert_transparency": [],
    "reverse_ip": [],
    "subdomains": [],
    "open_ports": [],
    "errors": []
}

def is_domain(target):
    try:
        socket.getaddrinfo(target, None)
        return True
    except:
        return False

def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except:
            return False

target_is_domain = is_domain(TARGET)
target_is_ip = is_ip(TARGET)

# --- DNS Reconnaissance ---
print("[*] Running DNS recon...")
dns_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "PTR", "CNAME"]
for dt in dns_types:
    try:
        import subprocess as sp
        r = sp.run(["dig", "+short", f"-{dt}", TARGET], capture_output=True, text=True, timeout=10)
        result = r.stdout.strip()
        if result:
            results["dns"][dt] = result

        # Also try nslookup for SPF/DMARC/DKIM TXT records
        if dt == "TXT":
            for record in ["_spf", "_dmarc", "_domainkey"]:
                try:
                    r2 = sp.run(["dig", "+short", "TXT", f"{record}.{TARGET}"],
                               capture_output=True, text=True, timeout=10)
                    if r2.stdout.strip():
                        results["dns"][f"TXT.{record}"] = r2.stdout.strip()
                except:
                    pass

        # Get additional TXT records
        r3 = sp.run(["dig", "+short", "TXT", TARGET], capture_output=True, text=True, timeout=10)
        if r3.stdout.strip():
            results["dns"]["TXT.all"] = r3.stdout.strip()

        time.sleep(0.3)
    except Exception as e:
        results["errors"].append(f"{dt} lookup failed: {str(e)[:100]}")

# --- WHOIS Lookup ---
print("[*] Running WHOIS lookup...")
try:
    r = subprocess.run(["whois", TARGET], capture_output=True, text=True, timeout=20)
    if r.stdout:
        results["whois"] = {
            "raw": r.stdout[:5000],
            "registrar": re.search(r'Registrar:(.*)', r.stdout, re.I),
            "creation_date": re.search(r'Creation Date:(.*)', r.stdout, re.I),
            "expiration_date": re.search(r'Expiration Date:(.*)', r.stdout, re.I),
            "name_servers": re.findall(r'Name Server:(.*)', r.stdout, re.I),
        }
        # Extract useful fields
        for field in ["registrar", "creation_date", "expiration_date", "name_servers"]:
            val = results["whois"].get(field)
            if val:
                if isinstance(val, list):
                    results["whois"][field] = [v.strip() for v in val]
                else:
                    results["whois"][field] = val.group(1).strip()
            else:
                del results["whois"][field]
except Exception as e:
    results["errors"].append(f"WHOIS error: {str(e)}")

# --- CRT.sh Certificate Transparency ---
print("[*] Searching certificate transparency (crt.sh)...")
try:
    r = requests.get(f"https://crt.sh/?q={quote(TARGET)}&output=json", timeout=20)
    if r.status_code == 200:
        try:
            data = r.json()
            seen = set()
            for entry in data[:100]:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.").strip()
                    if sub and sub not in seen:
                        seen.add(sub)
                        results["subdomains"].append({
                            "domain": sub,
                            "issuer": entry.get("issuer", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", "")
                        })
            results["cert_transparency"] = list(data[:5])
        except json.JSONDecodeError:
            results["errors"].append("crt.sh JSON parse error")
        time.sleep(1)
except Exception as e:
    results["errors"].append(f"crt.sh error: {str(e)}")

# --- ASN / IP Info (if target is domain, resolve first) ---
if target_is_domain or target_is_ip:
    print("[*] Looking up ASN info...")
    try:
        ip = TARGET if target_is_ip else results["dns"].get("A", TARGET)
        r = requests.get(f"https://api.bgpview.io/domain/{ip}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            results["asn"] = data.get("data", {})
    except Exception:
        pass

    # Fallback: ip-api.com
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                results["asn"]["ip_api"] = data
    except Exception as e:
        results["errors"].append(f"ASN lookup error: {str(e)}")

# --- Reverse IP Lookup ---
print("[*] Reverse IP lookup...")
try:
    ip = TARGET if target_is_ip else socket.gethostbyname(TARGET)
    r = requests.get(f"https://dns.bufferover.ai/api/v1/reverse/{ip}", timeout=15)
    if r.status_code == 200:
        data = r.json()
        results["reverse_ip"] = data.get("FDNS", [])[:50]
    time.sleep(1)
except Exception:
    pass

# --- Subdomain Discovery ---
print("[*] Discovering subdomains...")
# From crt.sh
for cert in results["subdomains"]:
    sub = cert["domain"]
    if sub and sub != TARGET and "." in sub:
        if sub.endswith("." + TARGET) or TARGET in sub:
            if sub not in [s["domain"] for s in results["subdomains"]]:
                results["subdomains"].append({"domain": sub, "source": "crt.sh"})

# From DNS dumping
try:
    r = requests.get(f"https://api.hackertarget.com/dnsdump/{TARGET}", timeout=20)
    if r.status_code == 200 and r.text:
        lines = r.text.strip().splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                rec_type = parts[1]
                name = parts[0].rstrip(".")
                if name and "." in name and name != TARGET:
                    results["subdomains"].append({"domain": name, "type": rec_type, "source": "hackertarget"})
    time.sleep(1)
except Exception as e:
    results["errors"].append(f"Subdomain discovery error: {str(e)}")

# --- Port Scanning (top 100 ports) ---
if target_is_domain or target_is_ip:
    print("[*] Scanning top 100 ports...")
    top_ports = [20,21,22,23,25,53,80,110,111,135,137,138,139,143,161,162,389,443,445,465,514,587,636,993,995,1433,1521,1723,2049,2082,2083,2086,2087,2095,2096,2080,2081,2084,2085,2088,2090,2091,2092,2093,2094,2097,2098,2099,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,3389,5432,553,5900,5901,5902,5903,5904,5905,5906,5907,5908,5909,5910,5911,5912,5913,5914,5915,5916]

    ip_to_scan = TARGET if target_is_ip else socket.gethostbyname(TARGET)
    for port in top_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_to_scan, port))
            if result == 0:
                results["open_ports"].append(port)
            sock.close()
        except:
            pass

# --- Cloud Bucket Enumeration ---
# Check common S3/GCS bucket names based on target
if target_is_domain:
    print("[*] Checking cloud buckets...")
    bucket_prefixes = ["", "files.", "api.", "cdn.", "static."]
    bucket_names = []
    parts = TARGET.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        for prefix in ["", "assets-", "data-", "backup-"]:
            bn = prefix + candidate.replace(".", "-")
            bucket_names.append(bn)
        bucket_names.append(candidate.replace(".", "-"))

    # Check S3 buckets via HTTP
    for bn in bucket_names[:30]:
        try:
            r = requests.head(f"http://{bn}.s3.amazonaws.com", timeout=3, allow_redirects=True)
            if r.status_code == 200:
                results["subdomains"].append({"domain": f"{bn}.s3.amazonaws.com", "bucket_s3": True})
            elif r.status_code == 302:
                results["subdomains"].append({"domain": f"{bn}.s3.amazonaws.com", "bucket_s3": "redirect", "location": r.headers.get("Location")})
        except:
            pass
        time.sleep(0.2)

with open(os.path.join(OUT_DIR, "infrastructure_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({
    "dns_records": len(results["dns"]),
    "subdomains_found": len(results["subdomains"]),
    "open_ports": results["open_ports"][:10],
    "cert_transparency": len(results["cert_transparency"])
}))