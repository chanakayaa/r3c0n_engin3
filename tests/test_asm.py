#!/usr/bin/env python3
"""
Offline tests for the ASM core and the threat-intel enrichment layer.

No network and no external recon tools are required: recon artifacts are
synthesized and intel feeds are served from an on-disk sample cache. Run with:

    python3 -m pytest tests/           # if pytest is available
    python3 tests/test_asm.py          # plain-stdlib fallback
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asm.intel import Enricher, extract_cve, risk_score          # noqa: E402
from asm.ingest import ingest_results, parse_nuclei_jsonl         # noqa: E402
from asm.models import Finding                                     # noqa: E402
from asm.store import Store                                        # noqa: E402
from asm.report import build_asm_report                            # noqa: E402

TARGET = "demo.example.com"


def _write_cache(cache_dir: Path) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2017-5638"},
        {"cveID": "CVE-2014-0160"}]}))
    (cache_dir / "epss.json").write_text(json.dumps({
        "CVE-2021-44228": 0.944, "CVE-2017-5638": 0.975,
        "CVE-2014-0160": 0.945, "CVE-2023-38831": 0.91, "CVE-2022-1234": 0.08}))


def _make_results(base: Path) -> None:
    recon = base / "recon"
    recon.mkdir(parents=True)
    (base / "scans").mkdir(parents=True)
    (recon / "subdomains.txt").write_text("www.demo.example.com\napp.demo.example.com")
    (recon / "alive_domains.txt").write_text(
        "https://www.demo.example.com\nhttps://app.demo.example.com")
    (recon / "domain_ips.txt").write_text("203.0.113.10")
    findings = [
        {"template-id": "CVE-2017-5638", "matched-at": "https://www.demo.example.com/u",
         "info": {"name": "Struts RCE", "severity": "critical"}},
        {"template-id": "CVE-2021-44228", "matched-at": "https://app.demo.example.com/a",
         "info": {"name": "Log4Shell", "severity": "critical"}},
        {"template-id": "CVE-2023-38831", "matched-at": "https://www.demo.example.com/d",
         "info": {"name": "WinRAR RCE", "severity": "high"}},
        {"template-id": "CVE-2022-1234", "matched-at": "https://app.demo.example.com",
         "info": {"name": "Low-exploit CVE", "severity": "medium"}},
        {"template-id": "tech-detect", "matched-at": "https://www.demo.example.com",
         "info": {"name": "Nginx", "severity": "info"}},
    ]
    (recon / "nuclei.jsonl").write_text("\n".join(json.dumps(f) for f in findings))


def test_risk_score_ordering():
    # KEV + high EPSS critical must outrank a high with EPSS but no KEV,
    # which must outrank a low-exploit medium.
    kev_crit = risk_score("critical", 0.97, True)
    high_epss = risk_score("high", 0.91, False)
    low_med = risk_score("medium", 0.08, False)
    assert kev_crit > high_epss > low_med
    assert kev_crit <= 100.0
    assert risk_score("info", None, False) < 10


def test_extract_cve():
    assert extract_cve(Finding("CVE-2021-44228", "x", "critical", "u")) == "CVE-2021-44228"
    assert extract_cve(Finding("exposed-git", "x", "medium", "u",
                               info={"tags": ["cve", "CVE-2019-0001"]})) == "CVE-2019-0001"
    assert extract_cve(Finding("tech-detect", "Nginx", "info", "u")) is None


def test_nuclei_parse_classification():
    text = json.dumps({"template-id": "generic", "matched-at": "u",
                       "info": {"name": "n", "severity": "high",
                                "classification": {"cve-id": ["CVE-2020-9999"]}}})
    f = parse_nuclei_jsonl(text)[0]
    assert extract_cve(f) == "CVE-2020-9999"


def test_end_to_end_enrich_and_prioritize():
    tmp = Path(tempfile.mkdtemp())
    cache = tmp / "cache"
    _write_cache(cache)
    run = tmp / "run"
    _make_results(run)

    result = ingest_results(TARGET, str(run))
    Enricher(cache_dir=cache, offline=True).enrich(result.findings)

    # Top finding after enrichment must be a KEV critical, not just any critical.
    top = result.findings[0]
    assert top.kev and top.risk_score >= 95, top

    store = Store(str(tmp / "asm.db"))
    sid = store.start_scan(TARGET, str(run))
    store.record_result(sid, result)

    rows = store.findings(TARGET)
    scores = [r["risk_score"] for r in rows]
    assert scores == sorted(scores, reverse=True), "findings must be risk-sorted"
    assert rows[0]["kev"] == 1

    html = Path(build_asm_report(store, TARGET, str(tmp / "r.html"))).read_text()
    assert "Risk</th>" in html and "CVE-2017-5638" in html
    store.close()


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")


if __name__ == "__main__":
    _run_all()
