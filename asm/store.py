"""
SQLite-backed asset inventory and change-detection engine.

This is what turns one-shot recon into Attack Surface Management: every scan
is recorded, assets and findings are tracked over time, and each new scan is
diffed against the target's previous scan to surface what changed.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Asset,
    Change,
    Finding,
    ScanResult,
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

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id, kind);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id, status);
CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id);
"""


class Store:
    """Thin SQLite wrapper with ASM-specific operations."""

    def __init__(self, path: str = "asm.db"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

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
            cur = self.conn.execute(
                "SELECT id FROM findings WHERE target_id=? AND dedupe_key=?",
                (target_id, dk),
            )
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE findings SET last_seen_at=?, last_scan_id=?, "
                    "status='open', severity=?, name=?, info=? WHERE id=?",
                    (now, scan_id, f.severity, f.name, info_json, row["id"]),
                )
            else:
                self.conn.execute(
                    "INSERT INTO findings(target_id, dedupe_key, template_id, name, "
                    "severity, matched_at, info, first_seen_at, last_seen_at, "
                    "first_scan_id, last_scan_id, status) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,'open')",
                    (target_id, dk, f.template_id, f.name, f.severity, f.matched_at,
                     info_json, now, now, scan_id, scan_id),
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
        rows.sort(key=lambda r: severity_rank(r["severity"]), reverse=True)
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
