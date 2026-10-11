"""
Configuration for ASM runs.

Config can come from a JSON file (``--config asm.config.json``) and/or CLI
flags; CLI flags win. Keeping this as plain JSON avoids a PyYAML dependency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class Config:
    db: str = "asm.db"
    results_root: str = "results"

    # vuln scanning
    vuln_scan: bool = True
    severities: List[str] = field(
        default_factory=lambda: ["critical", "high", "medium", "low"])
    nuclei_rate_limit: int = 150
    nuclei_templates: Optional[str] = None

    # recon toggles passed through to the recon engine
    crawl: bool = False
    dirs: bool = False

    # threat-intel enrichment & risk scoring
    intel_enrich: bool = True
    intel_offline: bool = False
    intel_cache_dir: Optional[str] = None

    # alerting
    webhook: Optional[str] = None
    slack_webhook: Optional[str] = None
    alert_min_severity: str = "low"

    @classmethod
    def load(cls, path: Optional[str]) -> "Config":
        if not path:
            return cls()
        data = json.loads(Path(path).read_text())
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def merge_args(self, args) -> "Config":
        """Overlay argparse Namespace values when explicitly provided."""
        for attr in ("db", "webhook", "slack_webhook", "nuclei_templates",
                     "alert_min_severity"):
            val = getattr(args, attr, None)
            if val is not None:
                setattr(self, attr, val)
        if getattr(args, "no_vuln", False):
            self.vuln_scan = False
        if getattr(args, "no_intel", False):
            self.intel_enrich = False
        if getattr(args, "offline", False):
            self.intel_offline = True
        if getattr(args, "crawl", False):
            self.crawl = True
        if getattr(args, "dirs", False):
            self.dirs = True
        if getattr(args, "severity", None):
            self.severities = [s.strip() for s in args.severity.split(",")
                               if s.strip()]
        return self

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)
