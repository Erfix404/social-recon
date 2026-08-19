#!/usr/bin/env python3
"""
Network/Shodan Recon Pipeline — Shodan, Censys, crt.sh, ASN, and infrastructure.
Finds hosts, open ports, vulnerabilities, SSL certs, and related infrastructure.

Requires API keys (optional but recommended):
- SHODAN_API_KEY
- CENSYS_API_ID / CENSYS_API_SECRET

Without keys, uses public endpoints (rate-limited).
"""
import sys, json, os, re, time, socket, subprocess, requests
from urllib.parse import quote

TARGET = sys.argv[1]
OUT_DIR = sys.argv[2]
os.makedirs(OUT_DIR, exist_ok=True)

results = {
    "target": TARGET,
    "shodan": {},
    "censys": {},
    "crt_sh": [],
    "asn": {},
    "reverse_ip": [],
    "subdomains": [],
    "open_ports": [],
    "vulnerabilities": [],
    "ssl_certs": [],
    "cloud_assets": [],
    "errors": []
}

SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
CENSYS_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_SECRET = os.environ.get("CENSYS_API_SECRET", "")

# --- Resolve target ---
def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except:
        return target

ip = resolve_ip(TARGET)

# --- Shodan ---
print("[*] Shodan lookup...")
if SHODAN_KEY:
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": SHODAN_KEY}, timeout=20)
        if r.status_code == 200:
            data = r.json()
            results["shodan"] = {
                "ip": data.get("ip_str"),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else [],
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "os": data.get("os"),
                "data": [{"port": d.get("port"), "transport": d.get("transport"), "product": d.get("product"), "version": d.get("version"), "data": d.get("data", "")[:200]} for d in data.get("data", [])[:5]],
            }
            results["open_ports"] = data.get("ports", [])
            results["vulnerabilities"] = list(data.get("vulns", {}).keys())[:10]
        elif r.status_code == 404:
            results["shodan"] = {"status": "no_results", "note": "Host not found in Shodan"}
        elif r.status_code == 403:
            results["shodan"] = {"status": "forbidden", "note": "Check API key"}
    except Exception as e:
        results["shodan"] = {"error": str(e)}
else:
    results["shodan"] = {"note": "SHODAN_API_KEY not set. Set env var for full Shodan results."}

# --- Censys ---
print("[*] Censys lookup...")
if CENSYS_ID and CENSYS_SECRET:
    try:
        r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                         auth=(CENSYS_ID, CENSYS_SECRET), timeout=20)
        if r.status_code == 200:
            data = r.json()
            host = data.get("result", {})
            results["censys"] = {
                "ip": host.get("ip"),
                "location": host.get("location", {}),
                "services": [{"port": s.get("port"), "service_name": s.get("service_name"), "transport_protocol": s.get("transport_protocol")} for s in host.get("services", [])[:10]],
                "operating_system": host.get("operating_system", {}),
                "software": [{"vendor": s.get("vendor"), "product": s.get("product"), "version": s.get("version")} for s in host.get("software", [])[:10]],
            }
        elif r.status_code == 404:
            results["censys"] = {"status": "no_results", "note": "Host not found in Censys"}
        elif r.status_code == 403:
            results["censys"] = {"status": "forbidden", "note": "Check Censys API credentials"}
    except Exception as e:
        results["censys"] = {"error": str(e)}
else:
    results["censys"] = {"note": "CENSYS_API_ID/CENSYS_API_SECRET not set."}

# --- CRT.sh Certificate Transparency ---
print("[*] CRT.sh lookup...")
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
                            "not_after": entry.get("not_after", ""),
                        })
            results["crt_sh"] = data[:5]
            # Extract SSL cert info
            for cert in data[:3]:
                results["ssl_certs"].append({
                    "domain": cert.get("name_value", ""),
                    "issuer": cert.get("issuer", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                })
            time.sleep(1)
        except json.JSONDecodeError:
            results["errors"].append("CRT.sh JSON parse error")
except Exception as e:
    results["errors"].append(f"CRT.sh error: {str(e)}")

# --- Reverse IP (BGPView) ---
print("[*] Reverse IP lookup...")
try:
    r = requests.get(f"https://api.bgpview.io/domain/{TARGET}", timeout=15)
    if r.status_code == 200:
        data = r.json()
        domain_info = data.get("data", {})
        if "subdomains" in domain_info:
            results["subdomains"].extend([{"domain": s, "source": "bgpview"} for s in domain_info.get("subdomains", [])[:50]])
    time.sleep(0.5)
except Exception:
    pass

# Reverse IP via HackerTarget
try:
    r = requests.get(f"https://api.hackertarget.com/reverseip/{TARGET}?api=", timeout=15)
    # This endpoint requires API key, skip if fails
except:
    pass

# --- Subdomain Discovery (HackerTarget + ViewDNS) ---
print("[*] Subdomain discovery...")
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
except Exception as e:
    results["errors"].append(f"Subdomain discovery error: {str(e)}")

# --- ASN Info ---
print("[*] ASN lookup...")
try:
    r = requests.get(f"https://api.bgpview.io/domain/{TARGET}", timeout=15)
    if r.status_code == 200:
        data = r.json()
        results["asn"] = {
            "domain_info": data.get("data", {}),
            "ip_blocks": data.get("data", {}).get("ip_blocks", [])[:5],
        }
except Exception:
    pass

# Fallback: ip-api.com
try:
    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
    if r.status_code == 200:
        data = r.json()
        if data.get("status") == "success":
            results["asn"]["ip_api"] = {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
except Exception as e:
    results["errors"].append(f"ASN lookup error: {str(e)}")

# --- Cloud Asset Enumeration ---
print("[*] Cloud bucket enumeration...")
bucket_prefixes = ["", "files.", "api.", "cdn.", "static.", "assets.", "data.", "backup-", "www."]
bucket_names = []
parts = TARGET.split(".")
for i in range(len(parts)):
    candidate = ".".join(parts[i:])
    for prefix in bucket_prefixes:
        bn = prefix + candidate.replace(".", "-")
        bucket_names.append(bn)
    bucket_names.append(candidate.replace(".", "-"))
    if candidate.replace(".", "-") not in bucket_names:
        bucket_names.append(candidate)

checked = set()
for bn in bucket_names[:30]:
    if bn in checked:
        continue
    checked.add(bn)
    # Check S3
    try:
        r = requests.head(f"http://{bn}.s3.amazonaws.com", timeout=3, allow_redirects=True)
        if r.status_code == 200:
            results["cloud_assets"].append({"type": "s3_bucket", "name": bn, "status": "open"})
        elif r.status_code == 302:
            results["cloud_assets"].append({"type": "s3_bucket", "name": bn, "status": "redirect"})
    except:
        pass
    # Check Azure
    try:
        r = requests.head(f"http://{bn}.blob.core.windows.net", timeout=3, allow_redirects=True)
        if r.status_code == 200:
            results["cloud_assets"].append({"type": "azure_blob", "name": bn, "status": "open"})
    except:
        pass
    # Check GCS
    try:
        r = requests.head(f"http://storage.googleapis.com/{bn}", timeout=3, allow_redirects=True)
        if r.status_code == 200:
            results["cloud_assets"].append({"type": "gcs_bucket", "name": bn, "status": "open"})
    except:
        pass
    time.sleep(0.1)

with open(os.path.join(OUT_DIR, "network_recon_results.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(json.dumps({
    "shodan": "found" if results.get("shodan", {}).get("ip") else "no_key",
    "censys": "found" if results.get("censys", {}).get("ip") else "no_key",
    "subdomains": len(results["subdomains"]),
    "cert_transparency": len(results["crt_sh"]),
    "ssl_certs": len(results["ssl_certs"]),
    "cloud_assets": len(results["cloud_assets"]),
    "asn": "found" if results.get("asn") else "no",
    "open_ports": results["open_ports"][:10],
    "vulns": len(results["vulnerabilities"])
}))