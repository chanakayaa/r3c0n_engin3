"""
SQLite-backed asset inventory and change-detection engine.

This is what turns one-shot recon into Attack Surface Management: every scan
is recorded, assets and findings are tracked over time, and each new scan is
diffed against the target's previous scan to surface what changed.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Criticality (1=low .. 5=critical) -> multiplier applied to a finding's risk.
CRITICALITY_MULT = {1: 0.7, 2: 0.85, 3: 1.0, 4: 1.2, 5: 1.5}


def _host_of(matched_at: str) -> str:
    """Extract the bare host from a finding location (url, host:port, host)."""
    s = re.sub(r"^\w+://", "", (matched_at or "").strip())
    s = s.split("/", 1)[0]          # drop any path
    s = s.rsplit(":", 1)[0] if s.count(":") == 1 else s  # drop :port (not IPv6)
    return s.strip().lower()

from .models import (
    Asset,
    Change,
    Finding,
    ScanResult,
    base_risk,
    severity_rank,
    utcnow,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES targets(id),
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'running',
    results_dir  TEXT,
    asset_count  INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id      INTEGER NOT NULL REFERENCES targets(id),
    kind           TEXT NOT NULL,
    key            TEXT NOT NULL,
    data           TEXT,
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    first_scan_id  INTEGER,
    last_scan_id   INTEGER,
    active         INTEGER NOT NULL DEFAULT 1,
    UNIQUE(target_id, kind, key)
);

CREATE TABLE IF NOT EXISTS scan_assets (
    scan_id  INTEGER NOT NULL REFERENCES scans(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    PRIMARY KEY (scan_id, asset_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL REFERENCES targets(id),
    dedupe_key    TEXT NOT NULL,
    template_id   TEXT,
    name          TEXT,
    severity      TEXT,
    matched_at    TEXT,
    info          TEXT,
    cve           TEXT,
    epss          REAL,
    kev           INTEGER NOT NULL DEFAULT 0,
    risk_score    REAL NOT NULL DEFAULT 0,
    attack            TEXT,
    attack_techniques TEXT,
    business_risk REAL NOT NULL DEFAULT 0,
    ticketed_at   TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    first_scan_id INTEGER,
    last_scan_id  INTEGER,
    status        TEXT NOT NULL DEFAULT 'open',
    UNIQUE(target_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id),
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    change_type TEXT NOT NULL,
    subject     TEXT NOT NULL,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

-- Directed relationships between assets (subdomain->ip, ip->service, ...).
CREATE TABLE IF NOT EXISTS asset_edges (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    src_id    INTEGER NOT NULL REFERENCES assets(id),
    dst_id    INTEGER NOT NULL REFERENCES assets(id),
    rel       TEXT NOT NULL,
    UNIQUE(target_id, src_id, dst_id, rel)
);

-- Business-context tags: glob patterns -> criticality / data sensitivity.
CREATE TABLE IF NOT EXISTS asset_tags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id),
    pattern     TEXT NOT NULL,
    kind        TEXT,
    criticality INTEGER NOT NULL DEFAULT 3,
    sensitivity TEXT,
    note        TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(target_id, pattern, kind)
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id, kind);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id, status);
CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON asset_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_tags_target ON asset_tags(target_id);
"""


class Store:
    """Thin SQLite wrapper with ASM-specific operations."""

    def __init__(self, path: str = "asm.db"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets the web UI read the inventory while a scan is writing to it.
        try:
            self.conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.OperationalError:
            pass
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release to older DBs."""
        cols = {r["name"] for r in
                self.conn.execute("PRAGMA table_info(findings)").fetchall()}
        for name, ddl in (
            ("cve", "ALTER TABLE findings ADD COLUMN cve TEXT"),
            ("epss", "ALTER TABLE findings ADD COLUMN epss REAL"),
            ("kev", "ALTER TABLE findings ADD COLUMN kev INTEGER NOT NULL DEFAULT 0"),
            ("risk_score",
             "ALTER TABLE findings ADD COLUMN risk_score REAL NOT NULL DEFAULT 0"),
            ("attack", "ALTER TABLE findings ADD COLUMN attack TEXT"),
            ("attack_techniques",
             "ALTER TABLE findings ADD COLUMN attack_techniques TEXT"),
            ("business_risk",
             "ALTER TABLE findings ADD COLUMN business_risk REAL NOT NULL DEFAULT 0"),
            ("ticketed_at", "ALTER TABLE findings ADD COLUMN ticketed_at TEXT"),
        ):
            if name not in cols:
                self.conn.execute(ddl)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # Targets & scans
    # ------------------------------------------------------------------ #

    def get_or_create_target(self, name: str) -> int:
        name = name.strip().lower()
        cur = self.conn.execute("SELECT id FROM targets WHERE name = ?", (name,))
        row = cur.fetchone()
        if row:
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO targets(name, created_at) VALUES(?, ?)",
            (name, utcnow()),
        )
        self.conn.commit()
        return cur.lastrowid

    def start_scan(self, target: str, results_dir: Optional[str] = None) -> int:
        target_id = self.get_or_create_target(target)
        cur = self.conn.execute(
            "INSERT INTO scans(target_id, started_at, status, results_dir) "
            "VALUES(?, ?, 'running', ?)",
            (target_id, utcnow(), results_dir),
        )
        self.conn.commit()
        return cur.lastrowid

    def previous_scan_id(self, target_id: int, before_scan_id: int) -> Optional[int]:
        cur = self.conn.execute(
            "SELECT id FROM scans WHERE target_id = ? AND id < ? "
            "AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (target_id, before_scan_id),
        )
        row = cur.fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------------ #
    # Ingestion of a completed scan
    # ------------------------------------------------------------------ #

    def record_result(self, scan_id: int, result: ScanResult) -> List[Change]:
        """Persist a ScanResult, then diff it against the previous scan.

        Returns the list of detected changes (also stored in the DB).
        """
        row = self.conn.execute(
            "SELECT target_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown scan_id {scan_id}")
        target_id = row["target_id"]

        prev_scan_id = self.previous_scan_id(target_id, scan_id)
        prev_assets = self._asset_keys_for_scan(prev_scan_id) if prev_scan_id else set()
        prev_findings = self._finding_keys_open(target_id)

        self._upsert_assets(target_id, scan_id, result.assets)
        self._record_edges(target_id, getattr(result, "edges", []) or [])
        self._upsert_findings(target_id, scan_id, result.findings)

        changes = self._diff(
            target_id,
            scan_id,
            prev_assets,
            prev_findings,
            result,
        )
        self._store_changes(target_id, scan_id, changes)

        now = utcnow()
        self.conn.execute(
            "UPDATE scans SET status='completed', finished_at=?, "
            "asset_count=?, finding_count=? WHERE id=?",
            (now, len(result.assets), len(result.findings), scan_id),
        )
        self.conn.commit()
        return changes

    def _upsert_assets(self, target_id: int, scan_id: int, assets: List[Asset]) -> None:
        now = utcnow()
        for a in assets:
            key = a.normalized_key()
            data_json = json.dumps(a.data, sort_keys=True)
            cur = self.conn.execute(
                "SELECT id FROM assets WHERE target_id=? AND kind=? AND key=?",
                (target_id, a.kind, key),
            )
            row = cur.fetchone()
            if row:
                asset_id = row["id"]
                self.conn.execute(
                    "UPDATE assets SET last_seen_at=?, last_scan_id=?, "
                    "active=1, data=? WHERE id=?",
                    (now, scan_id, data_json, asset_id),
                )
            else:
                cur = self.conn.execute(
                    "INSERT INTO assets(target_id, kind, key, data, first_seen_at, "
                    "last_seen_at, first_scan_id, last_scan_id, active) "
                    "VALUES(?,?,?,?,?,?,?,?,1)",
                    (target_id, a.kind, key, data_json, now, now, scan_id, scan_id),
                )
                asset_id = cur.lastrowid
            self.conn.execute(
                "INSERT OR IGNORE INTO scan_assets(scan_id, asset_id) VALUES(?, ?)",
                (scan_id, asset_id),
            )

    def _upsert_findings(self, target_id: int, scan_id: int,
                         findings: List[Finding]) -> None:
        now = utcnow()
        for f in findings:
            dk = f.dedupe_key()
            info_json = json.dumps(f.info, sort_keys=True)
            attack = getattr(f, "attack", None)
            attack_json = json.dumps(attack, sort_keys=True) if attack else None
            attack_tech = getattr(f, "attack_techniques", None) or None
            # Fall back to a severity-based risk so findings are still ranked
            # when intel enrichment is disabled or unavailable.
            rscore = f.risk_score if f.risk_score else base_risk(f.severity)
            cur = self.conn.execute(
                "SELECT id FROM findings WHERE target_id=? AND dedupe_key=?",
                (target_id, dk),
            )
            row = cur.fetchone()
            if row:
                # Preserve ticketed_at (set out-of-band); refresh everything else.
                self.conn.execute(
                    "UPDATE findings SET last_seen_at=?, last_scan_id=?, "
                    "status='open', severity=?, name=?, info=?, cve=?, epss=?, "
                    "kev=?, risk_score=?, attack=?, attack_techniques=? WHERE id=?",
                    (now, scan_id, f.severity, f.name, info_json, f.cve, f.epss,
                     1 if f.kev else 0, rscore, attack_json, attack_tech,
                     row["id"]),
                )
            else:
                self.conn.execute(
                    "INSERT INTO findings(target_id, dedupe_key, template_id, name, "
                    "severity, matched_at, info, cve, epss, kev, risk_score, "
                    "attack, attack_techniques, "
                    "first_seen_at, last_seen_at, first_scan_id, last_scan_id, status) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open')",
                    (target_id, dk, f.template_id, f.name, f.severity, f.matched_at,
                     info_json, f.cve, f.epss, 1 if f.kev else 0, rscore,
                     attack_json, attack_tech,
                     now, now, scan_id, scan_id),
                )

    # ------------------------------------------------------------------ #
    # Diffing
    # ------------------------------------------------------------------ #

    def _asset_keys_for_scan(self, scan_id: int) -> set:
        cur = self.conn.execute(
            "SELECT a.kind, a.key FROM assets a "
            "JOIN scan_assets sa ON sa.asset_id = a.id WHERE sa.scan_id = ?",
            (scan_id,),
        )
        return {(r["kind"], r["key"]) for r in cur.fetchall()}

    def _finding_keys_open(self, target_id: int) -> Dict[str, sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE target_id=? AND status='open'",
            (target_id,),
        )
        return {r["dedupe_key"]: r for r in cur.fetchall()}

    def _diff(self, target_id: int, scan_id: int, prev_assets: set,
              prev_findings: Dict[str, sqlite3.Row], result: ScanResult) -> List[Change]:
        changes: List[Change] = []

        current_assets = {(a.kind, a.normalized_key()) for a in result.assets}
        # First scan ever (no previous): don't flood with "added" noise.
        if prev_assets:
            for kind, key in sorted(current_assets - prev_assets):
                changes.append(Change("asset_added", f"{kind}:{key}",
                                      {"kind": kind, "key": key}))
            for kind, key in sorted(prev_assets - current_assets):
                changes.append(Change("asset_removed", f"{kind}:{key}",
                                      {"kind": kind, "key": key}))

        current_finding_keys = {f.dedupe_key() for f in result.findings}
        by_key = {f.dedupe_key(): f for f in result.findings}
        for dk in sorted(current_finding_keys - set(prev_findings)):
            f = by_key[dk]
            changes.append(Change("finding_new", dk, {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "matched_at": f.matched_at,
            }))
        # Findings open before but not seen now -> mark resolved.
        for dk in sorted(set(prev_findings) - current_finding_keys):
            row = prev_findings[dk]
            self.conn.execute(
                "UPDATE findings SET status='resolved', last_seen_at=? "
                "WHERE id=?",
                (utcnow(), row["id"]),
            )
            changes.append(Change("finding_resolved", dk, {
                "template_id": row["template_id"],
                "name": row["name"],
                "severity": row["severity"],
                "matched_at": row["matched_at"],
            }))

        return changes

    def _store_changes(self, target_id: int, scan_id: int,
                       changes: List[Change]) -> None:
        now = utcnow()
        for c in changes:
            self.conn.execute(
                "INSERT INTO changes(target_id, scan_id, change_type, subject, "
                "detail, created_at) VALUES(?,?,?,?,?,?)",
                (target_id, scan_id, c.change_type, c.subject,
                 json.dumps(c.detail, sort_keys=True), now),
            )

    # ------------------------------------------------------------------ #
    # Asset relationship graph
    # ------------------------------------------------------------------ #

    def _asset_id(self, target_id: int, kind: str, key: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM assets WHERE target_id=? AND kind=? AND key=?",
            (target_id, kind, (key or "").strip().lower()),
        ).fetchone()
        return row["id"] if row else None

    def _record_edges(self, target_id: int, edges: List[tuple]) -> None:
        """Persist (src, dst, rel) edges; endpoints are (kind, key) tuples.

        Endpoints that don't resolve to a stored asset are skipped silently.
        """
        for edge in edges:
            try:
                (sk, skey), (dk, dkey), rel = edge
            except (ValueError, TypeError):
                continue
            src = self._asset_id(target_id, sk, skey)
            dst = self._asset_id(target_id, dk, dkey)
            if src is None or dst is None or src == dst:
                continue
            self.conn.execute(
                "INSERT OR IGNORE INTO asset_edges(target_id, src_id, dst_id, rel) "
                "VALUES(?,?,?,?)",
                (target_id, src, dst, rel),
            )

    def graph(self, target: str) -> Dict[str, Any]:
        """Return the asset-relationship graph as {nodes, edges} for a target."""
        target_id = self._target_id(target)
        if target_id is None:
            return {"nodes": [], "edges": []}

        # Highest business/raw risk per host, to colour nodes by exposure.
        risk_by_host: Dict[str, float] = {}
        for f in self.conn.execute(
            "SELECT matched_at, business_risk, risk_score FROM findings "
            "WHERE target_id=? AND status='open'", (target_id,),
        ):
            host = _host_of(f["matched_at"])
            score = f["business_risk"] or f["risk_score"] or 0
            if host and score > risk_by_host.get(host, 0):
                risk_by_host[host] = score

        nodes = []
        for a in self.conn.execute(
            "SELECT id, kind, key FROM assets WHERE target_id=? AND active=1",
            (target_id,),
        ):
            nodes.append({
                "id": a["id"], "kind": a["kind"], "key": a["key"],
                "risk": round(risk_by_host.get(a["key"], 0), 1),
            })
        edges = [
            {"source": e["src_id"], "target": e["dst_id"], "rel": e["rel"]}
            for e in self.conn.execute(
                "SELECT src_id, dst_id, rel FROM asset_edges WHERE target_id=?",
                (target_id,),
            )
        ]
        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------ #
    # Business-context tagging & prioritisation
    # ------------------------------------------------------------------ #

    def set_tag(self, target: str, pattern: str, criticality: int = 3,
                kind: Optional[str] = None, sensitivity: Optional[str] = None,
                note: Optional[str] = None) -> None:
        target_id = self.get_or_create_target(target)
        criticality = max(1, min(5, int(criticality)))
        self.conn.execute(
            "INSERT INTO asset_tags(target_id, pattern, kind, criticality, "
            "sensitivity, note, created_at) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(target_id, pattern, kind) DO UPDATE SET "
            "criticality=excluded.criticality, sensitivity=excluded.sensitivity, "
            "note=excluded.note",
            (target_id, pattern.strip().lower(), kind, criticality,
             sensitivity, note, utcnow()),
        )
        self.conn.commit()

    def list_tags(self, target: str) -> List[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return []
        return self.conn.execute(
            "SELECT * FROM asset_tags WHERE target_id=? ORDER BY criticality DESC, "
            "pattern", (target_id,),
        ).fetchall()

    def criticality_for(self, target_id: int, host: str) -> int:
        """Best-matching tag criticality for a host (default 3 = medium)."""
        host = (host or "").strip().lower()
        best = 3
        matched = False
        for t in self.conn.execute(
            "SELECT pattern, criticality FROM asset_tags WHERE target_id=?",
            (target_id,),
        ):
            if fnmatch.fnmatch(host, t["pattern"]):
                # Most severe matching pattern wins.
                if not matched or t["criticality"] > best:
                    best = t["criticality"]
                matched = True
        return best

    def apply_business_risk(self, scan_id: int) -> None:
        """Blend each open finding's risk with its asset's criticality."""
        row = self.conn.execute(
            "SELECT target_id FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        if row is None:
            return
        target_id = row["target_id"]
        has_tags = self.conn.execute(
            "SELECT 1 FROM asset_tags WHERE target_id=? LIMIT 1", (target_id,)
        ).fetchone()
        for f in self.conn.execute(
            "SELECT id, matched_at, risk_score FROM findings WHERE target_id=?",
            (target_id,),
        ).fetchall():
            if has_tags:
                crit = self.criticality_for(target_id, _host_of(f["matched_at"]))
            else:
                crit = 3
            mult = CRITICALITY_MULT.get(crit, 1.0)
            business = round(min(100.0, (f["risk_score"] or 0) * mult), 1)
            self.conn.execute(
                "UPDATE findings SET business_risk=? WHERE id=?",
                (business, f["id"]),
            )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # Ticketing
    # ------------------------------------------------------------------ #

    def unticketed_findings(self, target_id: int,
                            min_rank: int) -> List[sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE target_id=? AND status='open' "
            "AND ticketed_at IS NULL", (target_id,),
        ).fetchall()
        return [r for r in rows if severity_rank(r["severity"]) >= min_rank]

    def mark_ticketed(self, finding_id: int) -> None:
        self.conn.execute(
            "UPDATE findings SET ticketed_at=? WHERE id=?", (utcnow(), finding_id)
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # Queries (for CLI / reporting)
    # ------------------------------------------------------------------ #

    def list_targets(self) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT t.*, "
            "(SELECT COUNT(*) FROM scans s WHERE s.target_id=t.id) AS scans, "
            "(SELECT COUNT(*) FROM assets a WHERE a.target_id=t.id AND a.active=1) "
            "AS active_assets "
            "FROM targets t ORDER BY t.name"
        ).fetchall()

    def assets(self, target: str, kind: Optional[str] = None,
               active_only: bool = True) -> List[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return []
        q = "SELECT * FROM assets WHERE target_id=?"
        params: List[Any] = [target_id]
        if kind:
            q += " AND kind=?"
            params.append(kind)
        if active_only:
            q += " AND active=1"
        q += " ORDER BY kind, key"
        return self.conn.execute(q, params).fetchall()

    def findings(self, target: str, status: str = "open",
                 min_severity: Optional[str] = None) -> List[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return []
        q = "SELECT * FROM findings WHERE target_id=?"
        params: List[Any] = [target_id]
        if status != "all":
            q += " AND status=?"
            params.append(status)
        rows = self.conn.execute(q, params).fetchall()
        if min_severity:
            floor = severity_rank(min_severity)
            rows = [r for r in rows if severity_rank(r["severity"]) >= floor]
        # Prioritize by business-adjusted risk when available, then raw risk,
        # then severity as a final tiebreaker.
        rows.sort(key=lambda r: (r["business_risk"] or 0, r["risk_score"] or 0,
                                 severity_rank(r["severity"])), reverse=True)
        return rows

    def latest_scan(self, target: str) -> Optional[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return None
        return self.conn.execute(
            "SELECT * FROM scans WHERE target_id=? AND status='completed' "
            "ORDER BY id DESC LIMIT 1",
            (target_id,),
        ).fetchone()

    def changes_for_scan(self, scan_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM changes WHERE scan_id=? ORDER BY change_type, subject",
            (scan_id,),
        ).fetchall()

    def changes_since(self, target: str, limit: int = 100) -> List[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return []
        return self.conn.execute(
            "SELECT * FROM changes WHERE target_id=? ORDER BY id DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()

    def scan_history(self, target: str, limit: int = 50) -> List[sqlite3.Row]:
        target_id = self._target_id(target)
        if target_id is None:
            return []
        return self.conn.execute(
            "SELECT * FROM scans WHERE target_id=? ORDER BY id DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()

    def _target_id(self, target: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM targets WHERE name=?", (target.strip().lower(),)
        ).fetchone()
        return row["id"] if row else None
