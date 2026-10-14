# 🛰 ReconEngine ASM — Guide

Attack Surface Management + vulnerability scanning on top of the ReconEngine
recon pipeline. This guide covers the `asm.py` command-line tool.

> ⚠️ **Authorized security testing only.** The ASM pipeline actively probes
> targets (DNS, HTTP, port scanning, and nuclei vulnerability checks). Only run
> it against assets you own or are explicitly authorized to test.

---

## How it works

Every ASM "pass" runs the same five stages:

```
recon  →  vulnerability scan  →  ingest  →  persist + diff  →  alert
```

1. **Recon** — reuses the existing `ReconEngine` pipeline (subdomains, DNS,
   live hosts, tech, TLS, headers, nmap, …) and writes artifacts under
   `results/<target>_<timestamp>/`.
2. **Vulnerability scan** — runs `nuclei` against the discovered live hosts.
3. **Ingest** — parses the recon artifacts (including `nmap.xml` and
   `nuclei.jsonl`) into a structured set of **assets** and **findings**.
4. **Persist + diff** — stores everything in a local SQLite inventory
   (`asm.db`) and compares this pass to the target's previous pass to produce a
   **changeset**.
5. **Alert** — summarizes new assets / new findings to the console and,
   optionally, to a webhook or Slack.

Because state is persistent, the second and later passes tell you **what
changed** — the core value of ASM — instead of dumping the whole surface again.

### Assets tracked

| Kind | Key format | Source |
|------|-----------|--------|
| `subdomain` | `sub.example.com` | subfinder / amass / assetfinder |
| `ip` | `93.184.216.34` | dnsx / nmap |
| `service` | `93.184.216.34:443` | nmap (open ports) |
| `url` | `www.example.com` | httpx (live hosts) |
| `technology` | `host|Nginx` | httpx tech-detect |

### Findings

Findings come from `nuclei` (de-duplicated by `template-id` + location) and
from a built-in **missing-security-headers** check. Each finding is tracked
with a status of `open` or `resolved`: if a finding seen in a previous scan is
absent in the current one, it is automatically marked **resolved** and a
`finding_resolved` change is recorded.

### Threat-intelligence enrichment & risk scoring

Raw severity isn't enough to decide what to fix first. After each vuln scan,
findings are enriched (see `asm/intel.py`) and assigned a **risk score (0–100)**
that blends three free, no-key data sources:

| Signal | Source | Meaning |
|--------|--------|---------|
| **KEV** | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | The CVE is **being exploited in the wild** right now |
| **EPSS** | [FIRST.org EPSS](https://www.first.org/epss/) | Probability (0–1) the CVE will be exploited in the next 30 days |
| **CVE / CVSS** | [NVD](https://nvd.nist.gov/) (optional) | Map a product+version/CPE to its CVEs (`--nvd`, honours `NVD_API_KEY`) |

```
risk = base(severity) + epss·40 + (20 if KEV) , capped at 100
```

So a **KEV critical with EPSS 0.97 scores ~99**, while a high-severity CVE with
no known exploitation and low EPSS scores far lower — the queue sorts by what
attackers are *actually* using. The formula is deliberately simple and
explainable.

CVE ids are extracted from the nuclei `template-id`, the `classification.cve-id`
field, and tags/references.

**Caching & offline behaviour.** KEV and EPSS responses are cached under
`~/.cache/recon-asm` (override with the `RECON_ASM_CACHE` env var or
`intel_cache_dir` in config), refreshed roughly daily. With `--offline` (or no
connectivity) enrichment uses only the cache; with neither network nor cache it
is skipped cleanly and the risk score falls back to severity alone.

Refresh the cache ahead of a scan:

```bash
python3 asm.py intel-update
```

Disable enrichment entirely with `--no-intel`.

---

## Commands

```
python3 asm.py <command> [options]
```

| Command | Purpose |
|---------|---------|
| `scan` | Run one full ASM pass for a target |
| `watch` | Run passes continuously on an interval |
| `ingest` | Import an existing `results/` directory into the inventory (no recon) |
| `targets` | List tracked targets |
| `assets` | List tracked assets for a target |
| `findings` | List findings for a target |
| `changes` | Show recorded changes for a target |
| `report` | Generate an ASM HTML report |
| `intel-update` | Refresh the local CISA KEV / EPSS intel cache |
| `tag` | Tag assets with a business criticality (glob pattern) |
| `tags` | List business-criticality tags for a target |
| `graph` | Export the asset-relationship graph (JSON or interactive HTML) |
| `export` | Export findings as JSON or CSV (ITSM/SIEM feed) |
| `serve` | Launch the web UI (needs the `[web]` extra) |
| `init` | Write a sample config file |

### Business-context prioritisation

Risk from EPSS/KEV answers "how exploitable", not "how much do *we* care". Tag
assets with a criticality (1=low .. 5=critical) and the score blends into a
**business risk** that drives sorting everywhere (CLI, report, UI, export):

```bash
asm tag  -t example.com --pattern "*.payments.example.com" --criticality 5 --sensitivity pii
asm tag  -t example.com --pattern "blog.example.com"       --criticality 1
asm tags -t example.com
```

Patterns are globs matched against each finding's host. `business_risk =
min(100, risk_score × multiplier)` with multipliers
`{1:0.7, 2:0.85, 3:1.0, 4:1.2, 5:1.5}` (untagged hosts default to 3). You can
also set these in the config file under `criticality`.

### MITRE ATT&CK tagging

Each finding is mapped to ATT&CK tactics/techniques from its nuclei tags,
template-id, name and CWE using a bundled keyword map
(`asm/data/attack_map.json` — extend it freely). Technique ids show in the CLI
`findings` view, the report and the export.

### Asset-relationship graph

```bash
asm graph -t example.com -o graph.json          # nodes + edges as JSON
asm graph -t example.com --html -o graph.html   # interactive page (cytoscape)
```

Edges: `subdomain → ip` (resolves_to), `ip → service` (exposes),
`host → technology` (runs), `subdomain → url` (http). Node size/ring reflects
the highest risk seen on that host. This is a read-only structural map — the
foundation for attack-path visualisation, not exploitation.

### ITSM / ticket webhook

Feed new findings to your own ticketing automation (section-13 integration):

```json
{ "ticket_webhook": "https://hooks.internal/asm", "ticket_min_severity": "high" }
```

Each **new** finding at or above the floor is POSTed once (flat JSON: name,
severity, cve, epss, kev, risk, business_risk, attack techniques, location) and
marked ticketed, so re-scans never duplicate. Point it at a Jira/ServiceNow
bridge or a SOAR webhook.

### Web UI

```bash
pip install '.[web]'
asm serve                      # http://127.0.0.1:8000
asm serve --host 0.0.0.0 --port 8080 --token "$(openssl rand -hex 16)"
```

Dashboard → start scans (background jobs with live logs) → per-target findings
(by business risk), asset graph, report download, JSON/CSV export. It starts
active scans: keep it on localhost or behind `--token` + a firewall, authorized
targets only.

### Export (SIEM/ITSM feed)

```bash
asm export -t example.com --format json -o findings.json
asm export -t example.com --format csv  -o findings.csv
```

### `scan`

```bash
python3 asm.py scan -t example.com \
    --crawl --dirs \
    --severity critical,high,medium \
    --slack-webhook https://hooks.slack.com/services/XXX \
    --alert-min-severity high
```

| Flag | Meaning |
|------|---------|
| `-t, --target` | Root domain to scan (required) |
| `--crawl` | Enable katana crawling in recon |
| `--dirs` | Enable feroxbuster directory brute-forcing in recon |
| `--no-vuln` | Skip the nuclei vulnerability scan |
| `--severity` | Comma list of nuclei severities (default `critical,high,medium,low`) |
| `--nuclei-templates` | Path to custom nuclei templates |
| `--webhook` | Generic JSON webhook for alerts |
| `--slack-webhook` | Slack incoming webhook for alerts |
| `--alert-min-severity` | Minimum finding severity that triggers an alert (default `low`) |
| `--db` | Inventory DB path (default `asm.db`) |
| `--config` | JSON config file (CLI flags override it) |

### `watch`

```bash
python3 asm.py watch -t example.com --interval 1440   # every 24h
```

`watch` loops in the foreground. For real deployments prefer `cron`
(see below) so the process survives reboots and doesn't hold a terminal.

### `findings`

```bash
python3 asm.py findings -t example.com --status open --min-severity medium
```

### `changes`

```bash
python3 asm.py changes -t example.com --limit 50
```

### `ingest`

Already ran recon separately? Pull it into the inventory without re-scanning:

```bash
python3 asm.py ingest -t example.com results/example.com_20260101_120000
```

---

## Config file

Generate a template:

```bash
python3 asm.py init -o asm.config.json
```

```json
{
  "db": "asm.db",
  "results_root": "results",
  "vuln_scan": true,
  "severities": ["critical", "high", "medium", "low"],
  "nuclei_rate_limit": 150,
  "nuclei_templates": null,
  "intel_enrich": true,
  "intel_offline": false,
  "intel_cache_dir": null,
  "ticket_webhook": null,
  "ticket_min_severity": "high",
  "criticality": [
    {"pattern": "*.payments.example.com", "criticality": 5, "sensitivity": "pii"}
  ],
  "crawl": false,
  "dirs": false,
  "webhook": null,
  "slack_webhook": null,
  "alert_min_severity": "low"
}
```

Use it with any command:

```bash
python3 asm.py scan -t example.com --config asm.config.json
```

CLI flags always override config-file values.

> 🔐 `asm.config.json` may hold webhook URLs — it is git-ignored by default.

---

## Scheduling continuous monitoring

### cron (recommended)

Daily scan at 02:30, logging output:

```cron
30 2 * * * cd /opt/r3c0n_engin3 && /usr/bin/python3 asm.py scan -t example.com \
    --config /opt/r3c0n_engin3/asm.config.json >> /var/log/asm-example.log 2>&1
```

### systemd timer

`/etc/systemd/system/asm-example.service`:

```ini
[Unit]
Description=ASM scan for example.com

[Service]
Type=oneshot
WorkingDirectory=/opt/r3c0n_engin3
ExecStart=/usr/bin/python3 asm.py scan -t example.com --config /opt/r3c0n_engin3/asm.config.json
```

`/etc/systemd/system/asm-example.timer`:

```ini
[Unit]
Description=Daily ASM scan for example.com

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now asm-example.timer
```

---

## Alert payloads

### Generic webhook (`--webhook`)

`POST application/json`:

```json
{
  "target": "example.com",
  "summary": "ASM report for example.com\n  new assets: 3 ...",
  "changes": [
    {"change_type": "asset_added", "subject": "subdomain:dev.example.com",
     "detail": {"kind": "subdomain", "key": "dev.example.com"}}
  ],
  "new_findings": [
    {"template_id": "CVE-2024-9999", "name": "Critical bug",
     "severity": "critical", "matched_at": "https://dev.example.com"}
  ]
}
```

### Slack (`--slack-webhook`)

Posts the formatted text summary as a Slack message.

An alert is only sent when something worth attention happened: a new finding at
or above `alert_min_severity`, a newly discovered asset, or a resolved finding.
The console summary always prints.

---

## Data model

Everything lives in a single SQLite file (`asm.db`):

* `targets` — tracked root domains
* `scans` — every pass, with status and counts
* `assets` + `scan_assets` — the inventory and which assets each scan observed
* `findings` — de-duplicated vulnerabilities with open/resolved status
* `changes` — the per-scan changeset

You can query it directly with any SQLite client for custom dashboards.
