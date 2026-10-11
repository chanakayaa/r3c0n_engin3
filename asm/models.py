"""Data models shared across the ASM package."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utcnow() -> str:
    """ISO-8601 UTC timestamp used everywhere for consistency."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Asset kinds tracked in the inventory. Keeping these as constants avoids
# typos leaking into the database and lets the diff engine group by kind.
KIND_SUBDOMAIN = "subdomain"
KIND_IP = "ip"
KIND_SERVICE = "service"       # key = "ip:port"
KIND_URL = "url"               # live http(s) endpoint
KIND_TECHNOLOGY = "technology" # key = "host|tech"

ASSET_KINDS = [
    KIND_SUBDOMAIN,
    KIND_IP,
    KIND_SERVICE,
    KIND_URL,
    KIND_TECHNOLOGY,
]

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


def severity_rank(sev: Optional[str]) -> int:
    return SEVERITY_ORDER.get((sev or "unknown").lower(), 0)


@dataclass
class Asset:
    """A single discovered asset belonging to a target."""

    kind: str
    key: str
    data: Dict[str, Any] = field(default_factory=dict)

    def normalized_key(self) -> str:
        return self.key.strip().lower()


@dataclass
class Finding:
    """A vulnerability / exposure finding (typically from nuclei)."""

    template_id: str
    name: str
    severity: str
    matched_at: str                      # url / host:port the finding hit
    info: Dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> str:
        # A finding is "the same" across scans when template + location match.
        return f"{self.template_id}|{self.matched_at}".strip().lower()


@dataclass
class Change:
    """A detected delta between two scans of the same target."""

    change_type: str          # asset_added | asset_removed | finding_new | finding_resolved
    subject: str              # the asset key or finding dedupe key
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Structured output of a single recon+scan pass, before persistence."""

    target: str
    results_dir: str
    assets: List[Asset] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow)
    finished_at: Optional[str] = None

    def add_asset(self, kind: str, key: str, **data: Any) -> None:
        key = (key or "").strip()
        if not key:
            return
        self.assets.append(Asset(kind=kind, key=key, data=data))

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
