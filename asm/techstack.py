"""
Technology-stack monitoring + published-vulnerability watch.

Aggregates the technologies fingerprinted during recon (httpx tech-detect,
whatweb) into a stack inventory per target, and — best effort, when online —
maps each technology to recently published CVEs via the NVD API so you learn
when a vulnerability is disclosed in something you actually run.

Honesty: keyword→CVE matching (without a precise CPE + version) is broad and
can over-match; results are labelled best-effort and meant as a watch signal,
not a definitive vulnerable/not-vulnerable verdict.
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Dict, List, Optional

from .intel import _http_get_json, NVD_URL
from .store import Store

# Noise words that show up as "technologies" but aren't worth CVE-watching.
_SKIP = {"html5", "javascript", "css", "json", "home", "index", "ok", "font",
         "http", "https", "title", "server"}


def tech_inventory(store: Store, target: str) -> List[Dict]:
    """Aggregate KIND_TECHNOLOGY assets into {tech, hosts, count}."""
    rows = store.assets(target, kind="technology", active_only=True)
    by_tech: Dict[str, set] = {}
    for a in rows:
        # key is "host|tech"
        if "|" not in a["key"]:
            continue
        host, tech = a["key"].split("|", 1)
        tech = tech.strip()
        if not tech or tech.lower() in _SKIP:
            continue
        by_tech.setdefault(tech, set()).add(host)
    return sorted(
        ({"technology": t, "hosts": sorted(h), "count": len(h)}
         for t, h in by_tech.items()),
        key=lambda x: x["count"], reverse=True)


def _nvd_keyword(tech: str, api_key: Optional[str], max_results: int = 5) -> List[Dict]:
    q = urllib.parse.urlencode({"keywordSearch": tech, "resultsPerPage": max_results})
    headers = {"User-Agent": "recon-engine-asm"}
    if api_key:
        headers["apiKey"] = api_key
    data = _http_get_json(f"{NVD_URL}?{q}", headers=headers)
    time.sleep(0.7 if api_key else 6.5)   # respect NVD rate limits
    out = []
    for item in (data or {}).get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                try:
                    score = metrics[k][0]["cvssData"]["baseScore"]
                    break
                except (KeyError, IndexError, TypeError):
                    pass
        out.append({"id": cve.get("id"), "cvss": score,
                    "published": cve.get("published", "")[:10]})
    return out


def stack_with_cves(store: Store, target: str, offline: bool = False,
                    api_key: Optional[str] = None,
                    limit_tech: int = 15) -> List[Dict]:
    """Inventory + best-effort CVE watch per technology."""
    inv = tech_inventory(store, target)
    if offline:
        return inv
    for entry in inv[:limit_tech]:
        entry["cves"] = _nvd_keyword(entry["technology"], api_key)
        entry["cve_count"] = len(entry["cves"])
    return inv
