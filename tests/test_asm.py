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
from asm.models import Finding, ScanResult                         # noqa: E402
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


# --------------------------------------------------------------------------- #
# Extensions: ATT&CK, business-context, graph, ticketing, web UI
# --------------------------------------------------------------------------- #

def _seed_full(tmp: Path) -> tuple:
    """Build a self-consistent results dir, ingest it, return (store, db_path)."""
    from asm.attack import annotate
    cache = tmp / "cache"
    _write_cache(cache)
    run = tmp / "run"
    recon = run / "recon"
    recon.mkdir(parents=True)
    (run / "scans").mkdir(parents=True)
    (recon / "subdomains.txt").write_text(
        "www.demo.example.com\napp.demo.example.com\napi.demo.example.com")
    (recon / "alive_domains.txt").write_text(
        "https://www.demo.example.com\nhttps://app.demo.example.com\n"
        "https://api.demo.example.com")
    (recon / "domain_ips.txt").write_text("203.0.113.10\n203.0.113.11")
    (recon / "host_ips.json").write_text(json.dumps({
        "www.demo.example.com": ["203.0.113.10"],
        "app.demo.example.com": ["203.0.113.10"],
        "api.demo.example.com": ["203.0.113.11"]}))
    (run / "scans" / "nmap.xml").write_text(
        '<?xml version="1.0"?><nmaprun>'
        '<host><address addr="203.0.113.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https"/></port></ports></host></nmaprun>')
    (recon / "nuclei.jsonl").write_text(json.dumps(
        {"template-id": "CVE-2021-44228",
         "matched-at": "https://app.demo.example.com/api",
         "info": {"name": "Log4Shell", "severity": "critical",
                  "tags": ["rce", "cve"]}}))

    result = ingest_results(TARGET, str(run))
    Enricher(cache_dir=cache, offline=True).enrich(result.findings)
    annotate(result.findings)
    store = Store(str(tmp / "ext.db"))
    sid = store.start_scan(TARGET, str(run))
    store.record_result(sid, result)
    store.apply_business_risk(sid)
    return store, sid


def test_attack_annotation():
    from asm.attack import annotate, map_finding
    f = Finding("CVE-2021-44228", "Log4Shell", "critical",
                "https://x", info={"tags": ["rce", "cve"]})
    techs = map_finding(f)
    assert any(t["technique_id"] == "T1203" for t in techs), techs
    annotate([f])
    assert "T1203" in f.attack_techniques


def test_business_risk_blend():
    tmp = Path(tempfile.mkdtemp())
    store, sid = _seed_full(tmp)
    before = {r["matched_at"]: r["business_risk"] for r in store.findings(TARGET)}
    # Tag the app host critical and re-blend.
    store.set_tag(TARGET, "app.*", criticality=5)
    store.apply_business_risk(sid)
    after = {r["matched_at"]: r["business_risk"] for r in store.findings(TARGET)}
    key = "https://app.demo.example.com/api"
    assert after[key] > before[key], (before[key], after[key])
    assert after[key] >= 100 or after[key] > store.findings(TARGET)[0]["risk_score"]
    store.close()


def test_graph_edges():
    tmp = Path(tempfile.mkdtemp())
    store, _ = _seed_full(tmp)
    g = store.graph(TARGET)
    rels = {e["rel"] for e in g["edges"]}
    assert {"resolves_to", "exposes", "http"} <= rels, rels
    assert len(g["nodes"]) >= 6
    store.close()


def test_ticket_idempotency(monkeypatch):
    import asm.monitor as monitor
    import asm.notify as notify
    tmp = Path(tempfile.mkdtemp())
    store, _ = _seed_full(tmp)
    calls = {"n": 0}
    # _dispatch_tickets does `from .notify import post_ticket` at call time.
    monkeypatch.setattr(notify, "post_ticket",
                        lambda url, row: calls.__setitem__("n", calls["n"] + 1) or True)
    cfg = type("C", (), {"ticket_webhook": "http://x", "ticket_min_severity": "high"})()
    monitor._dispatch_tickets(store, TARGET, cfg)
    first = calls["n"]
    monitor._dispatch_tickets(store, TARGET, cfg)   # nothing new -> no posts
    assert first >= 1 and calls["n"] == first, (first, calls["n"])
    store.close()


def test_risk_fallback_without_intel():
    # Findings must be ranked by severity even when the enricher never runs.
    tmp = Path(tempfile.mkdtemp())
    r = ScanResult(TARGET, str(tmp))
    r.add_finding(Finding("x-takeover", "Subdomain takeover", "high",
                          "https://dev.demo.example.com", info={"tags": ["takeover"]}))
    r.add_finding(Finding("x-git", "Exposed .git/config", "medium",
                          "https://demo.example.com/.git/config",
                          info={"tags": ["exposure"]}))
    store = Store(str(tmp / "nf.db"))
    sid = store.start_scan(TARGET)
    store.record_result(sid, r)          # no Enricher.enrich() at all
    store.apply_business_risk(sid)
    rows = store.findings(TARGET)
    assert all(row["risk_score"] > 0 for row in rows), "risk must not be 0"
    assert rows[0]["severity"] == "high", "high finding must sort first"
    store.close()


def test_ingest_merges_takeover_and_exposures():
    tmp = Path(tempfile.mkdtemp())
    recon = tmp / "recon"
    recon.mkdir(parents=True)
    (tmp / "scans").mkdir()
    (recon / "nuclei.jsonl").write_text(json.dumps(
        {"template-id": "CVE-1", "matched-at": "https://ex.com",
         "info": {"name": "c", "severity": "high"}}))
    (recon / "takeover.jsonl").write_text(json.dumps(
        {"template-id": "gh-takeover", "matched-at": "dev.ex.com",
         "info": {"name": "takeover", "severity": "high", "tags": ["takeover"]}}))
    # exposures file repeats the takeover line -> must de-duplicate
    (recon / "exposures.jsonl").write_text(
        json.dumps({"template-id": "git", "matched-at": "https://ex.com/.git/config",
                    "info": {"name": "git", "severity": "medium"}}) + "\n" +
        json.dumps({"template-id": "gh-takeover", "matched-at": "dev.ex.com",
                    "info": {"name": "takeover", "severity": "high"}}))
    res = ingest_results("ex.com", str(tmp))
    assert len(res.findings) == 3, [f.template_id for f in res.findings]


def test_appscan_extracts_secrets_and_assets():
    import zipfile
    from asm.appscan import scan_app, to_scan_result
    tmp = Path(tempfile.mkdtemp())
    apk = tmp / "app.apk"
    dex = (b"AKIAIOSFODNN7EXAMPLE sk_live_" + b"a" * 24 + b" "
           b"-----BEGIN RSA PRIVATE KEY----- "
           b"https://api.demo.example.com/v1 https://ext.other.com/x "
           b"assets.s3.amazonaws.com com.appsflyer.Lib")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", dex)
        z.writestr("AndroidManifest.xml", b"android.permission.INTERNET")
    scan = scan_app(str(apk), target="demo.example.com")
    types = {s["type"] for s in scan["secrets"]}
    assert "AWS Access Key ID" in types and "Private Key" in types, types
    assert "api.demo.example.com" in scan["subdomains"]
    assert any("s3.amazonaws.com" in b["ref"] for b in scan["buckets"])
    assert "AppsFlyer" in scan["trackers"]

    res = to_scan_result(scan, "demo.example.com")
    # discovered in-scope subdomain becomes a tracked asset
    assert any(a.kind == "subdomain" and a.key == "api.demo.example.com"
               for a in res.assets)
    # a secret becomes a finding
    assert any("Hardcoded secret" in f.name for f in res.findings)


def test_codescan_parsing():
    from asm.codescan import to_scan_result
    scan = {"target": "demo.example.com",
            "secrets": [{"type": "AWS Access Key ID", "severity": "high",
                         "value": "AKIAEXAMPLE", "location": "acme/app/config.js"}],
            "buckets": [{"type": "AWS S3 bucket", "ref": "a.s3.amazonaws.com"}],
            "subdomains": ["api.demo.example.com"], "urls": [], "files": ["acme/app/config.js"]}
    res = to_scan_result(scan, "demo.example.com")
    assert any(a.kind == "subdomain" and a.key == "api.demo.example.com" for a in res.assets)
    f = next(f for f in res.findings if "Leaked secret" in f.name)
    assert f.severity == "high" and f.matched_at == "acme/app/config.js"


def test_correlation_chains():
    from asm.correlate import correlate
    from asm.models import KIND_SUBDOMAIN, KIND_URL, KIND_SERVICE
    tmp = Path(tempfile.mkdtemp())
    r = ScanResult(TARGET, str(tmp))
    r.add_asset(KIND_SUBDOMAIN, "api.demo.example.com")
    r.add_asset(KIND_URL, "api.demo.example.com", url="https://api.demo.example.com")
    r.add_asset(KIND_SERVICE, "203.0.113.5:3306", ip="203.0.113.5", port="3306",
                service="mysql")
    r.add_finding(Finding("appsec-secret-aws", "Hardcoded secret in app: AWS Access Key ID",
                          "high", "app.apk", info={"tags": ["secret", "credential"]}))
    r.add_finding(Finding("git-config", "Exposed .git/config", "medium",
                          "https://api.demo.example.com/.git/config",
                          info={"tags": ["exposure"]}))
    store = Store(str(tmp / "c.db"))
    sid = store.start_scan(TARGET)
    store.record_result(sid, r)
    store.apply_business_risk(sid)
    chains = correlate(store, TARGET)
    names = " ".join(c.name for c in chains)
    assert any(c.template_id == "chain-cred-to-infra" for c in chains), names
    assert any("MySQL" in c.name for c in chains), names          # exposed DB port
    assert any("exposure" in c.template_id for c in chains), names  # .git on live host
    store.close()


def test_compliance_scoring():
    from asm.compliance import evaluate, evaluate_all
    tmp = Path(tempfile.mkdtemp())
    r = ScanResult(TARGET, str(tmp))
    r.add_finding(Finding("appsec-secret-aws", "Hardcoded secret in app: AWS Access Key ID",
                          "high", "app.apk", info={"tags": ["secret", "credential"]}))
    store = Store(str(tmp / "comp.db"))
    sid = store.start_scan(TARGET)
    store.record_result(sid, r)
    store.apply_business_risk(sid)
    dpdp = evaluate(store, TARGET, "dpdp")
    assert 0 <= dpdp["score"] <= 100
    byid = {c["id"]: c for c in dpdp["controls"]}
    assert byid["DPDP-LEAK"]["status"] == "fail"       # leaked secret fails data leakage
    assert byid["DPDP-5"]["status"] == "manual"        # consent is manual
    assert "iso27001" in evaluate_all(store, TARGET)
    store.close()


def test_techstack_inventory():
    from asm.techstack import tech_inventory
    from asm.models import KIND_TECHNOLOGY
    tmp = Path(tempfile.mkdtemp())
    r = ScanResult(TARGET, str(tmp))
    r.add_asset(KIND_TECHNOLOGY, "www.demo.example.com|nginx", host="www.demo.example.com")
    r.add_asset(KIND_TECHNOLOGY, "api.demo.example.com|nginx", host="api.demo.example.com")
    r.add_asset(KIND_TECHNOLOGY, "www.demo.example.com|php", host="www.demo.example.com")
    store = Store(str(tmp / "ts.db"))
    sid = store.start_scan(TARGET)
    store.record_result(sid, r)
    inv = tech_inventory(store, TARGET)
    nginx = next(t for t in inv if t["technology"] == "nginx")
    assert nginx["count"] == 2 and "www.demo.example.com" in nginx["hosts"]
    store.close()


def test_webapp_smoke():
    # Pure-stdlib server: start it on an ephemeral port and hit it with urllib.
    import urllib.request
    from asm import webapp
    from http.server import ThreadingHTTPServer
    tmp = Path(tempfile.mkdtemp())
    store, _ = _seed_full(tmp)
    store.close()
    webapp._STATE["db"] = str(tmp / "ext.db")
    webapp._STATE["runs_dir"] = tmp / ".runs"
    webapp._STATE["token"] = None
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        assert b"ReconEngine ASM" in urllib.request.urlopen(base + "/").read()
        assert urllib.request.urlopen(f"{base}/targets/{TARGET}").status == 200
        g = json.loads(urllib.request.urlopen(
            f"{base}/api/targets/{TARGET}/graph.json").read())
        assert len(g["edges"]) >= 3
        rep = urllib.request.urlopen(f"{base}/targets/{TARGET}/report").read()
        assert b"Attack Surface Report" in rep
    finally:
        httpd.shutdown()


# threading import needed by the stdlib webapp test
import threading  # noqa: E402


def _needs_monkeypatch(fn) -> bool:
    import inspect
    return "monkeypatch" in inspect.signature(fn).parameters


class _MonkeyPatch:
    """Minimal monkeypatch for the stdlib fallback runner."""
    def __init__(self):
        self._undo = []
    def setattr(self, obj, name, value):
        self._undo.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)
    def undo(self):
        for obj, name, old in reversed(self._undo):
            setattr(obj, name, old)


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            if _needs_monkeypatch(fn):
                mp = _MonkeyPatch()
                try:
                    fn(mp)
                finally:
                    mp.undo()
            else:
                fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")


if __name__ == "__main__":
    _run_all()
