"""
Orchestration: run one full ASM pass for a target.

A pass is:  recon  →  vulnerability scan  →  ingest  →  persist + diff  →  alert

This is the function a scheduler (cron / systemd timer / ``--watch``) calls on
every cycle. Each pass is recorded in the inventory and diffed against the
target's previous pass so only *changes* generate noise.
"""

from __future__ import annotations

import importlib
import sys
from argparse import Namespace
from pathlib import Path
from typing import List, Optional

from .config import Config
from .ingest import ingest_results
from .models import Change, Finding
from .notify import Notifier
from .store import Store
from .vuln import run_nuclei


def _import_recon_engine():
    """Import the root-level recon_engine module regardless of cwd."""
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return importlib.import_module("recon_engine")


def run_pass(target: str, config: Config,
             notifier: Optional[Notifier] = None) -> List[Change]:
    """Execute a single ASM pass. Returns the detected changes."""
    recon_engine = _import_recon_engine()

    store = Store(config.db)
    try:
        scan_id = store.start_scan(target)
        print(f"[+] ASM pass started (scan #{scan_id}) for {target}")

        # 1. Recon (reuses the existing ReconEngine pipeline).
        args = Namespace(target=target, crawl=config.crawl, dirs=config.dirs)
        engine = recon_engine.ReconEngine(args)
        engine.run_all()
        base_dir = Path(engine.base)

        # 2. Vulnerability scan against live hosts.
        if config.vuln_scan:
            alive = base_dir / "recon" / "alive_domains.txt"
            run_nuclei(
                targets_file=alive,
                output_file=base_dir / "recon" / "nuclei.jsonl",
                severities=config.severities,
                rate_limit=config.nuclei_rate_limit,
                templates=config.nuclei_templates,
            )

        # 3. Ingest artifacts into a structured result.
        result = ingest_results(target, str(base_dir))

        # 3b. Threat-intel enrichment + risk scoring (KEV / EPSS).
        if config.intel_enrich and result.findings:
            from .intel import Enricher  # lazy: avoids import cost when disabled
            from pathlib import Path as _Path
            cache = _Path(config.intel_cache_dir) if config.intel_cache_dir else None
            Enricher(cache_dir=cache, offline=config.intel_offline).enrich(
                result.findings)

        # 4. Persist + diff against previous pass.
        store.conn.execute(
            "UPDATE scans SET results_dir=? WHERE id=?", (str(base_dir), scan_id)
        )
        changes = store.record_result(scan_id, result)

        # 5. Alert.
        new_finding_keys = {c.subject for c in changes
                            if c.change_type == "finding_new"}
        new_findings: List[Finding] = [
            f for f in result.findings if f.dedupe_key() in new_finding_keys
        ]
        (notifier or Notifier(
            webhook=config.webhook,
            slack_webhook=config.slack_webhook,
            min_severity=config.alert_min_severity,
        )).dispatch(target, changes, new_findings)

        print(f"[✓] ASM pass #{scan_id} complete: "
              f"{len(result.assets)} assets, {len(result.findings)} findings, "
              f"{len(changes)} changes")
        return changes
    finally:
        store.close()
