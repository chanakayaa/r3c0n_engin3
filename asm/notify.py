"""
Alerting for ASM events.

Sends a summary of a scan's changes and new findings to one or more sinks:
console (always), a generic JSON webhook, and/or a Slack incoming webhook.
Uses only the standard library so it works without extra installs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from .models import Change, Finding, severity_rank


def _severity_emoji(sev: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get((sev or "").lower(), "⚪")


def summarize(target: str, changes: List[Change],
              new_findings: List[Finding]) -> str:
    """Human-readable summary used for console + Slack."""
    added = [c for c in changes if c.change_type == "asset_added"]
    removed = [c for c in changes if c.change_type == "asset_removed"]
    resolved = [c for c in changes if c.change_type == "finding_resolved"]

    lines = [f"ASM report for {target}"]
    lines.append(f"  new assets:       {len(added)}")
    lines.append(f"  removed assets:   {len(removed)}")
    lines.append(f"  new findings:     {len(new_findings)}")
    lines.append(f"  resolved findings:{len(resolved)}")

    if new_findings:
        lines.append("  ── new findings ──")
        for f in sorted(new_findings, key=lambda x: severity_rank(x.severity),
                        reverse=True)[:25]:
            lines.append(f"  {_severity_emoji(f.severity)} "
                         f"[{f.severity}] {f.name} @ {f.matched_at}")
    if added:
        lines.append("  ── new assets ──")
        for c in added[:40]:
            lines.append(f"  + {c.detail.get('kind')}: {c.detail.get('key')}")
    return "\n".join(lines)


class Notifier:
    def __init__(self, webhook: Optional[str] = None,
                 slack_webhook: Optional[str] = None,
                 min_severity: str = "low",
                 quiet: bool = False):
        self.webhook = webhook
        self.slack_webhook = slack_webhook
        self.min_severity = min_severity
        self.quiet = quiet

    def _worth_alerting(self, changes: List[Change],
                        new_findings: List[Finding]) -> bool:
        floor = severity_rank(self.min_severity)
        if any(severity_rank(f.severity) >= floor for f in new_findings):
            return True
        if any(c.change_type in ("asset_added", "finding_resolved")
               for c in changes):
            return True
        return False

    def dispatch(self, target: str, changes: List[Change],
                 new_findings: List[Finding]) -> None:
        summary = summarize(target, changes, new_findings)
        if not self.quiet:
            print("\n" + summary + "\n")

        if not self._worth_alerting(changes, new_findings):
            return

        payload = {
            "target": target,
            "summary": summary,
            "changes": [c.to_dict() for c in changes],
            "new_findings": [
                {
                    "template_id": f.template_id,
                    "name": f.name,
                    "severity": f.severity,
                    "matched_at": f.matched_at,
                }
                for f in new_findings
            ],
        }
        if self.webhook:
            self._post_json(self.webhook, payload)
        if self.slack_webhook:
            self._post_json(self.slack_webhook, {"text": "```\n" + summary + "\n```"})

    @staticmethod
    def _post_json(url: str, payload: Dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
        except (urllib.error.URLError, OSError) as exc:
            print(f"[!] notification to {url} failed: {exc}")
