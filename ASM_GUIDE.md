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
| `init` | Write a sample config file |

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
