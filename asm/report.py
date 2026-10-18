"""
ASM HTML report generator.

Unlike the original per-run ``report.py`` (which renders one recon directory),
this renders the *tracked* state of a target from the inventory DB: current
asset inventory, open findings by severity, and the history of changes over
time. Offline-safe (no external CSS/JS).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import List

from .models import severity_rank
from .store import Store

_CSS = """
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f172a;
color:#e5e7eb;margin:0;padding:24px;}
h1,h2{color:#38bdf8;} h1{margin-top:0;}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;}
.card{background:#1e293b;border-radius:10px;padding:14px 18px;min-width:120px;}
.card .n{font-size:28px;font-weight:700;} .card .l{color:#94a3b8;font-size:13px;}
table{border-collapse:collapse;width:100%;margin:10px 0;background:#020617;
border-radius:8px;overflow:hidden;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1e293b;
font-size:14px;vertical-align:top;}
th{background:#1e293b;color:#cbd5e1;}
.sev{font-weight:700;padding:2px 8px;border-radius:6px;font-size:12px;}
.critical{background:#7f1d1d;color:#fecaca;} .high{background:#9a3412;color:#fed7aa;}
.medium{background:#854d0e;color:#fde68a;} .low{background:#1e3a8a;color:#bfdbfe;}
.info,.unknown{background:#334155;color:#cbd5e1;}
.added{color:#4ade80;} .removed{color:#f87171;} .resolved{color:#38bdf8;}
details{background:#020617;border-radius:8px;padding:10px;margin:10px 0;}
summary{cursor:pointer;font-weight:700;}
.muted{color:#94a3b8;font-size:13px;}
"""


def _esc(x) -> str:
    return html.escape(str(x))


def _sev_badge(sev: str) -> str:
    sev = (sev or "unknown").lower()
    return f'<span class="sev {sev}">{_esc(sev)}</span>'


def build_asm_report(store: Store, target: str, out_path: str) -> str:
    latest = store.latest_scan(target)
    assets = store.assets(target, active_only=True)
    findings = store.findings(target, status="open")
    changes = store.changes_since(target, limit=200)
    history = store.scan_history(target, limit=25)

    kind_counts = Counter(a["kind"] for a in assets)
    sev_counts = Counter((f["severity"] or "unknown").lower() for f in findings)

    parts: List[str] = []
    parts.append(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 f"<title>ASM Report – {_esc(target)}</title>"
                 f"<style>{_CSS}</style></head><body>")
    parts.append(f"<h1>Attack Surface Report — {_esc(target)}</h1>")
    if latest:
        parts.append(f"<p class='muted'>Last completed scan #{latest['id']} "
                     f"at {_esc(latest['finished_at'])}</p>")

    # summary cards
    parts.append("<div class='cards'>")
    parts.append(f"<div class='card'><div class='n'>{len(assets)}</div>"
                 f"<div class='l'>active assets</div></div>")
    for kind in ("subdomain", "ip", "service", "url", "technology"):
        if kind_counts.get(kind):
            parts.append(f"<div class='card'><div class='n'>{kind_counts[kind]}"
                         f"</div><div class='l'>{kind}s</div></div>")
    parts.append(f"<div class='card'><div class='n'>{len(findings)}</div>"
                 f"<div class='l'>open findings</div></div>")
    parts.append("</div>")

    # findings
    parts.append("<h2>Open Findings</h2>")
    if sev_counts:
        parts.append("<div class='cards'>")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_counts.get(sev):
                parts.append(f"<div class='card'><div class='n'>{sev_counts[sev]}"
                             f"</div><div class='l'>{sev}</div></div>")
        parts.append("</div>")
    if findings:
        parts.append("<table><tr><th>Risk</th><th>Severity</th><th>KEV</th>"
                     "<th>EPSS</th><th>CVE</th><th>Name</th>"
                     "<th>Location</th><th>First seen</th></tr>")
        for f in findings:
            risk = f["risk_score"] or 0
            kev = ("<span class='sev critical'>KEV</span>" if f["kev"] else
                   "<span class='muted'>—</span>")
            epss = f"{f['epss']:.2f}" if f["epss"] is not None else "—"
            cve = _esc(f["cve"]) if f["cve"] else "<span class='muted'>—</span>"
            parts.append(
                f"<tr><td><b>{risk:.1f}</b></td>"
                f"<td>{_sev_badge(f['severity'])}</td>"
                f"<td>{kev}</td><td>{epss}</td><td>{cve}</td>"
                f"<td>{_esc(f['name'])}</td>"
                f"<td>{_esc(f['matched_at'])}</td>"
                f"<td class='muted'>{_esc(f['first_seen_at'])}</td></tr>")
        parts.append("</table>")
        parts.append("<p class='muted'>Risk = severity blended with EPSS "
                     "(exploit probability) and CISA KEV (known-exploited). "
                     "Higher = fix first.</p>")
    else:
        parts.append("<p class='muted'>No open findings.</p>")

    # inventory
    parts.append("<h2>Asset Inventory</h2>")
    by_kind: dict = {}
    for a in assets:
        by_kind.setdefault(a["kind"], []).append(a)
    for kind in sorted(by_kind):
        rows = by_kind[kind]
        parts.append(f"<details><summary>{_esc(kind)} ({len(rows)})</summary>")
        parts.append("<table><tr><th>Asset</th><th>First seen</th>"
                     "<th>Last seen</th></tr>")
        for a in rows:
            parts.append(
                f"<tr><td>{_esc(a['key'])}</td>"
                f"<td class='muted'>{_esc(a['first_seen_at'])}</td>"
                f"<td class='muted'>{_esc(a['last_seen_at'])}</td></tr>")
        parts.append("</table></details>")

    # changes
    parts.append("<h2>Recent Changes</h2>")
    if changes:
        parts.append("<table><tr><th>When</th><th>Type</th><th>Subject</th></tr>")
        cls = {"asset_added": "added", "asset_removed": "removed",
               "finding_new": "high", "finding_resolved": "resolved"}
        for c in changes:
            klass = cls.get(c["change_type"], "")
            parts.append(
                f"<tr><td class='muted'>{_esc(c['created_at'])}</td>"
                f"<td class='{klass}'>{_esc(c['change_type'])}</td>"
                f"<td>{_esc(c['subject'])}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class='muted'>No changes recorded yet.</p>")

    # scan history
    parts.append("<h2>Scan History</h2><table><tr><th>#</th><th>Started</th>"
                 "<th>Finished</th><th>Assets</th><th>Findings</th></tr>")
    for s in history:
        parts.append(
            f"<tr><td>{s['id']}</td><td class='muted'>{_esc(s['started_at'])}</td>"
            f"<td class='muted'>{_esc(s['finished_at'])}</td>"
            f"<td>{s['asset_count']}</td><td>{s['finding_count']}</td></tr>")
    parts.append("</table>")

    parts.append("</body></html>")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(parts))
    return str(out)
