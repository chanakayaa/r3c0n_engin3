"""
Threat-intelligence enrichment & risk scoring.

Turns raw findings into a *prioritized* queue by fusing three free data
sources — exactly the signals a commercial ASM uses to say "fix this one first":

  * CISA KEV   – is this CVE *known to be exploited in the wild*?
  * EPSS       – probability (0..1) the CVE will be exploited in the next 30d
  * NVD        – (optional) map a product+version/CPE to its CVEs & CVSS

All clients are cache-backed and degrade gracefully: with no network and no
cache they simply add no enrichment, and the risk score falls back to severity.

Data sources (all free, no key required except optional NVD key):
  KEV  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS : https://api.first.org/data/v1/epss?cve=CVE-...
  NVD  : https://services.nvd.nist.gov/rest/json/cves/2.0

Network goes through urllib, which honours HTTPS_PROXY / SSL_CERT_FILE, so it
works behind corporate proxies as well as on a plain WSL/Ubuntu box.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import Finding, severity_rank

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Base points per severity before intel boosts.
_SEV_BASE = {"critical": 40, "high": 32, "medium": 22, "low": 12,
             "info": 3, "unknown": 8}


def default_cache_dir() -> Path:
    env = os.environ.get("RECON_ASM_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "recon-asm"


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    bundle = (os.environ.get("SSL_CERT_FILE")
              or os.environ.get("REQUESTS_CA_BUNDLE"))
    if bundle and Path(bundle).exists():
        try:
            ctx.load_verify_locations(bundle)
        except ssl.SSLError:
            pass
    return ctx


def _http_get_json(url: str, timeout: int = 30,
                   headers: Optional[Dict[str, str]] = None) -> Optional[dict]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent":
                                 "recon-engine-asm"})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_context()) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as exc:  # network, TLS, JSON, HTTP – all non-fatal
        print(f"[!] intel fetch failed ({url.split('?')[0]}): {exc}")
        return None


def extract_cve(finding: Finding) -> Optional[str]:
    """Pull a CVE id out of a finding (template id, classification, or tags)."""
    m = CVE_RE.search(finding.template_id or "")
    if m:
        return m.group(0).upper()
    info = finding.info or {}
    classification = info.get("classification") or {}
    cve_ids = classification.get("cve-id") or classification.get("cve_id")
    if isinstance(cve_ids, list) and cve_ids:
        return str(cve_ids[0]).upper()
    if isinstance(cve_ids, str) and cve_ids:
        return cve_ids.upper()
    for field in (info.get("tags"), info.get("reference")):
        text = " ".join(field) if isinstance(field, list) else str(field or "")
        m = CVE_RE.search(text)
        if m:
            return m.group(0).upper()
    m = CVE_RE.search(finding.name or "")
    return m.group(0).upper() if m else None


def risk_score(severity: str, epss: Optional[float], kev: bool,
               exposure: float = 1.0) -> float:
    """Blend severity, exploit-probability and known-exploitation into 0..100.

    A KEV critical lands near 100; a plain info with no CVE stays near 3. The
    formula is intentionally simple and explainable (not a black box).
    """
    base = _SEV_BASE.get((severity or "unknown").lower(), 8)
    score = float(base)
    if epss is not None:
        score += epss * 40.0
    if kev:
        score += 20.0
    score *= max(0.1, min(1.0, exposure))
    return round(min(100.0, score), 1)


class _JsonCache:
    def __init__(self, path: Path, ttl_seconds: int):
        self.path = path
        self.ttl = ttl_seconds

    def load(self) -> Optional[dict]:
        if not self.path.exists():
            return None
        if self.ttl and (time.time() - self.path.stat().st_mtime) > self.ttl:
            return None  # stale
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    def load_any_age(self) -> Optional[dict]:
        """Load even if stale – used as an offline fallback."""
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data))


class KEVClient:
    """CISA Known Exploited Vulnerabilities catalog (cached ~1 day)."""

    def __init__(self, cache_dir: Path, offline: bool = False,
                 ttl_seconds: int = 86400):
        self.cache = _JsonCache(cache_dir / "kev.json", ttl_seconds)
        self.offline = offline
        self._set: Optional[set] = None

    def _catalog_to_set(self, catalog: dict) -> set:
        vulns = catalog.get("vulnerabilities", []) if catalog else []
        return {str(v.get("cveID", "")).upper() for v in vulns if v.get("cveID")}

    def refresh(self) -> int:
        catalog = _http_get_json(KEV_URL)
        if catalog and catalog.get("vulnerabilities") is not None:
            self.cache.save(catalog)
            self._set = self._catalog_to_set(catalog)
            return len(self._set)
        return 0

    def _ensure(self) -> set:
        if self._set is not None:
            return self._set
        catalog = self.cache.load()
        if catalog is None and not self.offline:
            if self.refresh():
                return self._set or set()
            catalog = self.cache.load_any_age()
        elif catalog is None and self.offline:
            catalog = self.cache.load_any_age()
        self._set = self._catalog_to_set(catalog or {})
        return self._set

    def is_kev(self, cve: Optional[str]) -> bool:
        if not cve:
            return False
        return cve.upper() in self._ensure()


class EPSSClient:
    """FIRST.org EPSS scores, cached per-CVE with a rolling TTL."""

    def __init__(self, cache_dir: Path, offline: bool = False,
                 ttl_seconds: int = 86400):
        self.cache = _JsonCache(cache_dir / "epss.json", ttl_seconds)
        self.offline = offline
        self._scores: Dict[str, float] = {}
        cached = self.cache.load_any_age() or {}
        if isinstance(cached, dict):
            self._scores = {k.upper(): float(v) for k, v in cached.items()
                            if isinstance(v, (int, float))}

    def _persist(self) -> None:
        self.cache.save(self._scores)

    def scores(self, cves: Iterable[str]) -> Dict[str, float]:
        wanted = {c.upper() for c in cves if c}
        missing = [c for c in wanted if c not in self._scores]
        if missing and not self.offline:
            self._fetch(missing)
        return {c: self._scores[c] for c in wanted if c in self._scores}

    def _fetch(self, cves: List[str]) -> None:
        # EPSS API accepts a comma list; chunk to keep URLs sane.
        for i in range(0, len(cves), 80):
            chunk = cves[i:i + 80]
            q = urllib.parse.urlencode({"cve": ",".join(chunk)})
            data = _http_get_json(f"{EPSS_URL}?{q}")
            if not data:
                continue
            for row in data.get("data", []):
                cve = str(row.get("cve", "")).upper()
                try:
                    self._scores[cve] = float(row.get("epss"))
                except (TypeError, ValueError):
                    continue
        self._persist()

    def get(self, cve: Optional[str]) -> Optional[float]:
        if not cve:
            return None
        return self._scores.get(cve.upper())


class NVDClient:
    """Optional: map a CPE / keyword to CVEs via the NVD 2.0 API.

    Rate-limited (5 req/30s without a key, 50 with NVD_API_KEY); best-effort and
    cached. Disabled unless explicitly requested, so it never slows a scan by
    default.
    """

    def __init__(self, cache_dir: Path, offline: bool = False):
        self.cache_dir = cache_dir / "nvd"
        self.offline = offline
        self.api_key = os.environ.get("NVD_API_KEY")

    def cves_for_cpe(self, cpe: str, limit: int = 20) -> List[Dict]:
        if self.offline or not cpe:
            return []
        cache = _JsonCache(self.cache_dir / (re.sub(r"[^\w.-]", "_", cpe) + ".json"),
                           ttl_seconds=7 * 86400)
        cached = cache.load()
        if cached is not None:
            return cached.get("cves", [])
        q = urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": limit})
        headers = {"User-Agent": "recon-engine-asm"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        data = _http_get_json(f"{NVD_URL}?{q}", headers=headers)
        time.sleep(0.6 if self.api_key else 6.0)  # respect rate limits
        out: List[Dict] = []
        for item in (data or {}).get("vulnerabilities", []):
            cve = item.get("cve", {})
            out.append({
                "id": cve.get("id"),
                "cvss": _nvd_cvss(cve),
            })
        cache.save({"cves": out})
        return out


def _nvd_cvss(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return None


class Enricher:
    """Enrich a list of findings in place with CVE intel and a risk score."""

    def __init__(self, cache_dir: Optional[Path] = None, offline: bool = False):
        cache_dir = cache_dir or default_cache_dir()
        self.kev = KEVClient(cache_dir, offline=offline)
        self.epss = EPSSClient(cache_dir, offline=offline)
        self.offline = offline

    def refresh_feeds(self) -> Dict[str, int]:
        n = self.kev.refresh()
        return {"kev_entries": n}

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        # Resolve CVEs first, then batch the EPSS lookup for efficiency.
        cves = []
        for f in findings:
            f.cve = extract_cve(f)
            if f.cve:
                cves.append(f.cve)
        epss_map = self.epss.scores(cves) if cves else {}
        for f in findings:
            f.epss = epss_map.get(f.cve) if f.cve else None
            f.kev = self.kev.is_kev(f.cve)
            f.risk_score = risk_score(f.severity, f.epss, f.kev)
        findings.sort(key=lambda x: x.risk_score, reverse=True)
        return findings
