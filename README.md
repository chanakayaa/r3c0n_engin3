### 🚀 ReconEngine v9.2 – Pentest Recon & Intelligence Framework

**ReconEngine** is an advanced, modular **reconnaissance and intelligence automation framework** designed for **penetration testers, SOC teams, red teams, and auditors**. It performs deep attack surface discovery and produces **interactive, executive-ready HTML reports** with expandable modules and raw terminal-style evidence.

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
