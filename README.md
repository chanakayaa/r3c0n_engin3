### 🚀 ReconEngine – ASM Monitoring & Vulnerability Scanning Framework

**ReconEngine** is an advanced, modular **Attack Surface Management (ASM) and vulnerability-scanning framework** designed for **penetration testers, SOC teams, red teams, and auditors**. It performs deep attack surface discovery, **tracks your external footprint over time**, runs **integrated vulnerability scanning (nuclei)**, **alerts on changes and new findings**, and produces **interactive, executive-ready HTML reports**.

Two layers ship together:

| Layer | Entry point | What it does |
|-------|-------------|--------------|
| **Recon engine** | `recon_engine.py` | One-shot deep reconnaissance + nuclei vuln scan, writing artifacts to `results/` |
| **ASM platform** | `asm.py` | Persistent asset inventory, change detection (diffing), vuln tracking, alerting, continuous monitoring |

---

## 🛰 Attack Surface Management (ASM)

The ASM layer (`asm.py`) adds the "monitoring" half of the tool on top of recon:

* **Persistent asset inventory** — every subdomain, IP, service (`ip:port`), live URL and technology is stored in a local SQLite database (`asm.db`) and tracked across scans.
* **Change detection / diffing** — each scan is compared to the previous one for the same target. New subdomains, newly-opened ports, and surface shrink are surfaced automatically; the first scan establishes a silent baseline.
* **Vulnerability tracking** — nuclei findings are de-duplicated by template + location, so you see *new* findings and *resolved* findings, not the same list every run.
* **Alerting** — new assets and new findings can be pushed to a generic JSON webhook or a Slack incoming webhook, with a configurable severity floor.
* **Continuous monitoring** — run on an interval with `asm.py watch`, or (recommended for production) from `cron` / a systemd timer.

```bash
# One ASM pass: recon + vuln scan + inventory update + diff + alert
python3 asm.py scan -t example.com --slack-webhook https://hooks.slack.com/services/XXX

# What's new since last time?
python3 asm.py changes -t example.com

# Current open findings, high and above
python3 asm.py findings -t example.com --min-severity high

# Full ASM report (inventory + findings + change history)
python3 asm.py report -t example.com -o example_asm.html

# Continuous monitoring, daily
python3 asm.py watch -t example.com --interval 1440
```

See [`ASM_GUIDE.md`](ASM_GUIDE.md) for the complete command reference, config file format, and scheduling recipes.

---

## 📦 Original one-shot recon framework

**ReconEngine** performs deep attack surface discovery and produces **interactive, executive-ready HTML reports** with expandable modules and raw terminal-style evidence.

---

## 🔐 Key Features

### 🔍 Comprehensive Reconnaissance

* ASN mapping & WHOIS intelligence
* Passive + active subdomain enumeration
* DNS resolution & IP discovery
* Live host detection
* CDN & origin identification
* WAF detection
* TLS / SSL configuration analysis

### 🧠 Technology & Exposure Analysis

* Technology fingerprinting via **Httpx**
* Deep fingerprinting via **WhatWeb**
* Authentication & API surface mapping
* Historical URL discovery (Wayback / GAU)
* Google dork generation
* Email & OSINT harvesting

### 🛡 Security Misconfiguration Detection

* Missing / weak HTTP security headers
* TLS weaknesses
* Server & framework exposure
* WAF presence and behavior insights

### 🔎 Scanning & Enumeration

* Automated Nmap scanning
* Structured scan artifacts (normal, XML, grepable)
* Organized results per engagement

---

## 📊 Advanced Reporting Engine

ReconEngine includes a **dedicated report generator** that creates a fully interactive HTML report:

* Executive summary for management
* Expandable module-wise sections
* Intelligent summaries per module (not filenames)
* Terminal-style **“View Raw Data”** evidence
* Offline-safe (no CDN / JS frameworks)
* Audit-friendly and compliance-ready

---

## 📁 Output Structure

```text
results/
└── target_timestamp/
    ├── recon/
    │   ├── subdomains.txt
    │   ├── alive_domains.txt
    │   ├── technologies_httpx.txt
    │   ├── whatweb_tech.txt
    │   ├── security_headers_raw.json
    │   └── ...
    ├── scans/
    │   ├── nmap.nmap
    │   ├── nmap.xml
    │   └── nmap.gnmap
    └── reports/
        └── detailed_report.html
```

---

## ▶️ Usage

### Run Recon

```bash
python3 main.py -t example.com --crawl --dirs
```

### Generate Report

```bash
python3 report.py results/example.com_YYYYMMDD_HHMMSS
```


## ⚠️ Disclaimer

> ReconEngine is intended **only for authorized security testing**.
> The author is not responsible for misuse or illegal activities.

---

---

## 👤 Author

**Pushkar Singh**
Security Researcher | Pentester | 
