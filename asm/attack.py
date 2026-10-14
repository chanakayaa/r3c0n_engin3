"""
MITRE ATT&CK tagging for findings (lightweight, offline).

nuclei findings rarely carry explicit ATT&CK technique ids, but their tags,
template-id, name and CWE strongly imply a technique. This module maps those
signals to ATT&CK tactics/techniques using a bundled, curated keyword table
(``data/attack_map.json``) so findings can be grouped and reported the way the
OICL tender's section-5 ("MITRE ATT&CK-mapped") expects.

This is classification, not attack execution.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

from .models import Finding

_DATA = Path(__file__).resolve().parent / "data" / "attack_map.json"
_WORD = re.compile(r"[a-z0-9.]+")


@lru_cache(maxsize=1)
def _load_map() -> Dict[str, List[Dict[str, str]]]:
    try:
        return json.loads(_DATA.read_text()).get("map", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _signal_tokens(finding: Finding) -> set:
    """Collect lowercased signal tokens from a finding to match against keys."""
    parts: List[str] = [finding.template_id or "", finding.name or ""]
    info = finding.info or {}
    tags = info.get("tags")
    if isinstance(tags, list):
        parts.extend(str(t) for t in tags)
    elif tags:
        parts.append(str(tags))
    classification = info.get("classification") or {}
    cwe = classification.get("cwe-id") or classification.get("cwe_id")
    if isinstance(cwe, list):
        parts.extend(str(c) for c in cwe)
    elif cwe:
        parts.append(str(cwe))
    text = " ".join(parts).lower()
    return set(_WORD.findall(text))


def map_finding(finding: Finding) -> List[Dict[str, str]]:
    """Return the de-duplicated ATT&CK techniques implied by a finding."""
    amap = _load_map()
    if not amap:
        return []
    tokens = _signal_tokens(finding)
    # A map key matches when it appears as a whole token, or (for hyphenated
    # keys like "default-login") when all of its parts are present.
    seen = set()
    out: List[Dict[str, str]] = []
    for key, techniques in amap.items():
        parts = key.split("-")
        if key in tokens or all(p in tokens for p in parts):
            for tech in techniques:
                tid = tech.get("technique_id")
                if tid and tid not in seen:
                    seen.add(tid)
                    out.append(tech)
    return out


def annotate(findings: List[Finding]) -> List[Finding]:
    """Attach ATT&CK mappings to each finding in place."""
    for f in findings:
        f.attack = map_finding(f)
        f.attack_techniques = ",".join(
            t["technique_id"] for t in f.attack if t.get("technique_id"))
    return findings
