#!/usr/bin/env python3
"""
ReconEngine v9.2 – Detailed HTML Report Generator
Author: Pushkar Singh
"""

import re
import json
from pathlib import Path
from datetime import datetime

# ================= CONFIG =================

RECON_FILES = {
    "ASN Information": "asn.txt",
    "WHOIS Information": "whois.txt",
    "Subdomain Enumeration": "subdomains.txt",
    "Live Domains": "alive_domains.txt",
    "Resolved IPs": "domain_ips.txt",
    "CDN Detection": "cdn_origin.txt",
    "WAF Detection": "waf.txt",
    "Technology Fingerprinting (Httpx)": "technologies_httpx.txt",
    "Technology Fingerprinting (WhatWeb)": "whatweb_tech.txt",
    "TLS / SSL Analysis": "tls.txt",
    "Security Headers": "security_headers_raw.json",
    "Authentication Surface": "auth_surface.txt",
    "API Endpoints": "api_endpoints.txt",
    "Historical URLs": "historical_urls.txt",
    "Google Dorks": "google_dorks.txt",
    "Email Harvesting": "harvester_raw.txt"
}

SCAN_FILES = {
    "Nmap Scan (Normal)": "nmap.nmap",
    "Nmap Scan (XML)": "nmap.xml",
    "Nmap Grepable": "nmap.gnmap"
}

# ================= HELPERS =================

def html_escape(text):
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

def read_file(path):
    try:
        return path.read_text(errors="ignore")
    except:
        return "No data available"

# ================= SMART MODULE SUMMARY =================

def module_summary(title, path):
    if not path.exists():
        return "No data available"

    text = path.read_text(errors="ignore")
    lines = [l for l in text.splitlines() if l.strip()]

    if "Email Harvesting" in title:
        emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+", text))
        return f"Emails discovered: {len(emails)}"

    if "Subdomain" in title:
        return f"Subdomains discovered: {len(lines)}"

    if "Live Domains" in title:
        return f"Live hosts identified: {len(lines)}"

    if "Resolved IPs" in title:
        return f"Unique IPs resolved: {len(set(lines))}"

    if "Technology Fingerprinting (WhatWeb)" in title:
        techs = sum(1 for l in lines if l.startswith("-"))
        return f"Technologies identified: {techs}"

    if "Technology Fingerprinting (Httpx)" in title:
        return f"Technologies detected via httpx: {len(lines)}"

    if "Security Headers" in title:
        try:
            data = json.loads(text)
            missing = sum(
                1 for entry in data
                for v in entry.get("headers", {}).values()
                if v == "missing"
            )
            return f"Missing security headers detected: {missing}"
        except:
            return "Security headers analyzed"

    if "TLS" in title:
        weak = sum(1 for l in lines if "weak" in l.lower())
        return f"TLS reviewed, weak indicators: {weak}"

    if "WAF" in title:
        detected = sum(1 for l in lines if "is behind" in l.lower())
        return f"WAF detected on {detected} hosts"

    return f"Entries found: {len(lines)}"

# ================= EXECUTIVE SUMMARY =================

def executive_summary(recon_dir, scan_dir):
    items = []
    items.append(f"<li><b>Scan Date:</b> {datetime.now()}</li>")

    if (recon_dir / "subdomains.txt").exists():
        items.append(f"<li><b>Subdomains:</b> {len((recon_dir/'subdomains.txt').read_text().splitlines())}</li>")

    if (recon_dir / "alive_domains.txt").exists():
        items.append(f"<li><b>Live Domains:</b> {len((recon_dir/'alive_domains.txt').read_text().splitlines())}</li>")

    if (scan_dir / "nmap.nmap").exists():
        items.append("<li><b>Port Scan:</b> Completed</li>")

    if (recon_dir / "security_headers_raw.json").exists():
        items.append("<li><b>Security Headers:</b> Analysis Performed</li>")

    if (recon_dir / "whatweb_tech.txt").exists():
        items.append("<li><b>Technology Fingerprinting:</b> Completed</li>")

    return "<ul>" + "\n".join(items) + "</ul>"

# ================= REPORT BUILDER =================

def build_report(base_dir):
    recon_dir = base_dir / "recon"
    scan_dir = base_dir / "scans"
    report_dir = base_dir / "reports"
    report_dir.mkdir(exist_ok=True)

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>ReconEngine Detailed Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
    padding: 20px;
}}
h1, h2 {{
    color: #38bdf8;
}}
details {{
    background: #020617;
    padding: 12px;
    margin-bottom: 10px;
    border-radius: 6px;
}}
summary {{
    cursor: pointer;
    font-size: 16px;
    font-weight: bold;
}}
pre {{
    background: #000;
    color: #00ff00;
    padding: 10px;
    overflow-x: auto;
    border-radius: 6px;
    max-height: 400px;
}}
.section {{
    margin-bottom: 30px;
}}
</style>
</head>

<body>

<h1>ReconEngine v9.2 – Detailed Recon Report</h1>

<div class="section">
<h2>Executive Summary</h2>
{executive_summary(recon_dir, scan_dir)}
</div>

<div class="section">
<h2>Reconnaissance Modules</h2>
"""

    for title, file in RECON_FILES.items():
        p = recon_dir / file
        raw = html_escape(read_file(p))
        summary = module_summary(title, p)

        html += f"""
<details>
<summary>{title}</summary>
<p><b>Summary:</b> {summary}</p>
<details>
<summary>View Raw Data</summary>
<pre>{raw}</pre>
</details>
</details>
"""

    html += """
<div class="section">
<h2>Scanning Results</h2>
"""

    for title, file in SCAN_FILES.items():
        p = scan_dir / file
        raw = html_escape(read_file(p))

        html += f"""
<details>
<summary>{title}</summary>
<details>
<summary>View Raw Scan Output</summary>
<pre>{raw}</pre>
</details>
</details>
"""

    html += """
</div>
</body>
</html>
"""

    output = report_dir / "detailed_report.html"
    output.write_text(html)
    print(f"[✓] Report generated: {output}")

# ================= ENTRY =================

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 report.py <results/target_timestamp>")
        sys.exit(1)

    base = Path(sys.argv[1])
    build_report(base)
