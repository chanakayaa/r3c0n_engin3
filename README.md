### 🚀 ReconEngine – ASM Monitoring & Vulnerability Scanning Framework

**ReconEngine** is an advanced, modular **Attack Surface Management (ASM) and vulnerability-scanning framework** designed for **penetration testers, SOC teams, red teams, and auditors**. It performs deep attack surface discovery, **tracks your external footprint over time**, runs **integrated vulnerability scanning (nuclei)**, **alerts on changes and new findings**, and produces **interactive, executive-ready HTML reports**.

Two layers ship together:

| Layer | Entry point | What it does |
|-------|-------------|--------------|
| **Recon engine** | `recon_engine.py` | One-shot deep reconnaissance + nuclei vuln scan, writing artifacts to `results/` |
| **ASM platform** | `asm.py` | Persistent asset inventory, change detection (diffing), vuln tracking, alerting, continuous monitoring |

---

## 📥 Install

The recon layer drives external tools (`subfinder`, `httpx`, `nmap`, `nuclei`, …)
installed by [`setup.sh`](setup.sh). The Python package itself installs with pip
and puts an `asm` command on your PATH:

```bash
git clone https://github.com/chanakayaa/r3c0n_engin3.git
cd r3c0n_engin3

# (recommended) isolate in a virtualenv
python3 -m venv .venv && source .venv/bin/activate

pip install .          # or:  pip install -e .   for a live/editable install
```

This installs two commands:

| Command | Equivalent to | Purpose |
|---------|---------------|---------|
| `asm` | `python3 asm.py` | ASM platform (scan, watch, findings, report, …) |
| `recon-engine` | `python3 recon_engine.py` | One-shot recon pipeline |

```bash
asm --help
asm intel-update                 # pull live CISA KEV / EPSS into the cache
asm scan -t example.com          # authorized targets only
```

> You can always run it without installing, straight from the repo:
> `python3 asm.py <command>`. The ASM core is standard-library only; `tqdm`
> (progress bars) is the sole pip dependency.

---

## 🛰 Attack Surface Management (ASM)

The ASM layer (`asm.py`) adds the "monitoring" half of the tool on top of recon:

* **Persistent asset inventory** — every subdomain, IP, service (`ip:port`), live URL and technology is stored in a local SQLite database (`asm.db`) and tracked across scans.
* **Change detection / diffing** — each scan is compared to the previous one for the same target. New subdomains, newly-opened ports, and surface shrink are surfaced automatically; the first scan establishes a silent baseline.
* **Vulnerability tracking** — nuclei findings are de-duplicated by template + location, so you see *new* findings and *resolved* findings, not the same list every run.
* **Threat-intel risk scoring** — every finding is enriched with **CISA KEV** (known-exploited) and **EPSS** (exploit probability) and given a 0–100 **risk score**, so the queue is sorted by what attackers are actually using — not raw severity. Cached & offline-capable; free, no API key.
* **MITRE ATT&CK tagging** — findings are mapped to ATT&CK tactics/techniques from their nuclei tags/CWE, so results line up with an ATT&CK-based plan.
* **Business-context prioritisation** — tag assets with a criticality (`asm tag`) and the risk score blends into a **business risk** that ranks what matters to *you*, not just raw CVSS/EPSS.
* **Asset-relationship graph** — a read-only map (subdomain → IP → service → technology) exported as JSON or an interactive HTML page; the foundation for attack-surface/path visualisation.
* **ITSM feed** — POST each new finding (above a severity floor) to a generic ticket webhook your SOAR/Jira/ServiceNow bridge consumes; idempotent, one ticket per finding.
* **Mobile app attack surface (BeVigil-style)** — `asm appscan` statically analyses an APK/IPA for hardcoded secrets (keys/tokens/private keys), cloud buckets, and back-end subdomains/endpoints, folding the discovered assets into the ASM inventory and the secrets into prioritised findings.
* **Public code secret leaks** — `asm codescan` searches public GitHub code for the target's leaked secrets and back-end subdomains (needs a GitHub token), folding them into the inventory.
* **Attack-path correlation** — `asm correlate` chains individual signals into exploit paths (leaked key + exposed bucket = exfiltration; `.git` on a live host = source disclosure; DB port + default login = breach), elevated above single findings.
* **Compliance posture — ISO 27001 + DPDP** — `asm compliance` scores each framework from the observed attack surface; per control it shows the control point, how to achieve it, and the evidence the tool found (policy controls flagged for manual attestation). A posture indicator, not a certification.
* **Tech-stack monitoring** — `asm techstack` inventories every fingerprinted technology across the surface and (online) watches NVD for newly published CVEs affecting them.
* **Live scan tracker** — a real-time, auto-refreshing view of running recon/app/code jobs in the web UI.
* **REST API + Docker** — a versioned JSON API (`/api/v1/...`) for SIEM/SOAR/CI integration, and an all-in-one Docker image that bundles the scanning toolchain.
* **Web UI** — a polished, animated console (`asm serve`) to launch **every** scan type (recon / app / code), watch live job logs, browse prioritised findings, view the asset graph and download reports. **Pure standard library — no pip install, runs on any Python 3.9+.**

### Web UI

No install needed — the UI is pure standard library:

```bash
asm serve                     # http://127.0.0.1:8000  (localhost-only)
asm serve --host 0.0.0.0 --port 8080 --token "$(openssl rand -hex 16)"
# or, without installing the package at all:
python -m asm serve
```

The animated console launches **every** scan type from the browser — Recon,
App (APK/IPA), and Code leaks — as background jobs with a live-streaming log,
and links to each target's prioritised findings, asset graph, report download
and JSON/CSV export. It **initiates active scans**, so keep it bound to
localhost (or behind `--token` + a firewall) and use it only against authorized
targets.
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
