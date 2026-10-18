"""
Unified command-line interface for ReconEngine ASM.

Subcommands
-----------
  scan      run one ASM pass (recon + vuln scan + inventory + diff + alert)
  watch     run passes continuously on an interval
  ingest    import an existing recon results directory into the inventory
  targets   list tracked targets
  assets    list tracked assets for a target
  findings  list findings for a target
  changes   show recorded changes for a target
  report    generate an ASM HTML report for a target
  tag       tag assets with a business criticality (glob pattern)
  tags      list business-criticality tags for a target
  graph     export the asset-relationship graph (JSON or HTML)
  export    export findings as JSON or CSV (ITSM/SIEM feed)
  appscan   static-analyse an APK/IPA for secrets + hidden assets
  codescan  search public GitHub code for leaked secrets
  serve     launch the web UI (pure stdlib, no dependencies)
  intel-update  refresh the local CISA KEV / EPSS cache
  init      write a sample config file

Authorized security testing only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .config import Config
from .ingest import ingest_results
from .models import severity_rank
from .monitor import run_pass
from .notify import Notifier
from .report import build_asm_report
from .store import Store

BANNER = r"""
  ____                       _____             _
 |  _ \ ___  ___ ___  _ __  | ____|_ __   __ _(_)_ __   ___
 | |_) / _ \/ __/ _ \| '_ \ |  _| | '_ \ / _` | | '_ \ / _ \
 |  _ <  __/ (_| (_) | | | || |___| | | | (_| | | | | |  __/
 |_| \_\___|\___\___/|_| |_||_____|_| |_|\__, |_|_| |_|\___|
         ASM Monitoring & Vulnerability  |___/  Scanner
         Authorized Security Testing Only
"""


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="path to JSON config file")
    p.add_argument("--db", help="inventory database path (default asm.db)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asm", description="ReconEngine ASM")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="run one ASM pass for a target")
    sp.add_argument("-t", "--target", required=True)
    sp.add_argument("--crawl", action="store_true")
    sp.add_argument("--dirs", action="store_true")
    sp.add_argument("--no-vuln", action="store_true", help="skip vuln scanning")
    sp.add_argument("--no-intel", action="store_true",
                    help="skip KEV/EPSS enrichment & risk scoring")
    sp.add_argument("--offline", action="store_true",
                    help="use only cached intel (no network for KEV/EPSS)")
    sp.add_argument("--severity", help="comma list, e.g. critical,high,medium")
    sp.add_argument("--nuclei-templates", help="custom nuclei template path")
    sp.add_argument("--webhook", help="generic JSON webhook for alerts")
    sp.add_argument("--slack-webhook", help="Slack incoming webhook for alerts")
    sp.add_argument("--alert-min-severity", help="floor for alerting (default low)")
    _add_common(sp)

    wp = sub.add_parser("watch", help="run passes continuously on an interval")
    wp.add_argument("-t", "--target", required=True)
    wp.add_argument("--interval", type=int, default=1440,
                    help="minutes between passes (default 1440 = daily)")
    wp.add_argument("--crawl", action="store_true")
    wp.add_argument("--dirs", action="store_true")
    wp.add_argument("--no-vuln", action="store_true")
    wp.add_argument("--no-intel", action="store_true")
    wp.add_argument("--offline", action="store_true")
    wp.add_argument("--severity")
    wp.add_argument("--nuclei-templates")
    wp.add_argument("--webhook")
    wp.add_argument("--slack-webhook")
    wp.add_argument("--alert-min-severity")
    _add_common(wp)

    ip = sub.add_parser("ingest", help="import an existing results directory")
    ip.add_argument("-t", "--target", required=True)
    ip.add_argument("results_dir")
    ip.add_argument("--no-intel", action="store_true")
    ip.add_argument("--offline", action="store_true")
    _add_common(ip)

    up = sub.add_parser("intel-update",
                        help="refresh the local KEV/EPSS intel cache")
    _add_common(up)

    tp = sub.add_parser("targets", help="list tracked targets")
    _add_common(tp)

    ap = sub.add_parser("assets", help="list assets for a target")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("--kind", help="filter by kind")
    ap.add_argument("--all", action="store_true", help="include inactive assets")
    _add_common(ap)

    fp = sub.add_parser("findings", help="list findings for a target")
    fp.add_argument("-t", "--target", required=True)
    fp.add_argument("--status", default="open",
                    choices=["open", "resolved", "all"])
    fp.add_argument("--min-severity", help="floor, e.g. medium")
    _add_common(fp)

    cp = sub.add_parser("changes", help="show recorded changes for a target")
    cp.add_argument("-t", "--target", required=True)
    cp.add_argument("--limit", type=int, default=50)
    _add_common(cp)

    rp = sub.add_parser("report", help="generate an ASM HTML report")
    rp.add_argument("-t", "--target", required=True)
    rp.add_argument("-o", "--output", help="output html path")
    _add_common(rp)

    tgp = sub.add_parser("tag", help="tag assets with business criticality")
    tgp.add_argument("-t", "--target", required=True)
    tgp.add_argument("--pattern", required=True,
                     help="glob over host, e.g. '*.payments.example.com'")
    tgp.add_argument("--criticality", type=int, default=3,
                     choices=[1, 2, 3, 4, 5], help="1=low .. 5=critical")
    tgp.add_argument("--kind", help="restrict to an asset kind (optional)")
    tgp.add_argument("--sensitivity", help="e.g. pii, phi, financial")
    tgp.add_argument("--note")
    _add_common(tgp)

    tlp = sub.add_parser("tags", help="list business-criticality tags")
    tlp.add_argument("-t", "--target", required=True)
    _add_common(tlp)

    gp = sub.add_parser("graph", help="export the asset-relationship graph")
    gp.add_argument("-t", "--target", required=True)
    gp.add_argument("-o", "--output", help="output path")
    gp.add_argument("--html", action="store_true",
                    help="emit an interactive HTML page instead of JSON")
    _add_common(gp)

    ep = sub.add_parser("export", help="export findings (JSON or CSV)")
    ep.add_argument("-t", "--target", required=True)
    ep.add_argument("--format", choices=["json", "csv"], default="json")
    ep.add_argument("-o", "--output", help="output path")
    _add_common(ep)

    asp = sub.add_parser("appscan",
                         help="static-analyse an APK/IPA for secrets + assets")
    asp.add_argument("-t", "--target", required=True,
                     help="root domain to fold discovered assets into")
    asp.add_argument("--apk", action="append", help="APK file (repeatable)")
    asp.add_argument("--ipa", action="append", help="IPA file (repeatable)")
    asp.add_argument("-o", "--out", help="write BeVigil-style JSON report")
    asp.add_argument("--no-intel", action="store_true")
    asp.add_argument("--offline", action="store_true")
    _add_common(asp)

    csp = sub.add_parser("codescan",
                         help="search public GitHub code for leaked secrets")
    csp.add_argument("-t", "--target", required=True)
    csp.add_argument("--github-token", help="GitHub token (or GITHUB_TOKEN env)")
    csp.add_argument("--org", help="limit search to a GitHub org")
    csp.add_argument("--max-files", type=int, default=30)
    csp.add_argument("-o", "--out", help="write JSON report")
    csp.add_argument("--no-intel", action="store_true")
    csp.add_argument("--offline", action="store_true")
    _add_common(csp)

    svp = sub.add_parser("serve", help="launch the stdlib web UI (no deps)")
    svp.add_argument("--host", default="127.0.0.1")
    svp.add_argument("--port", type=int, default=8000)
    svp.add_argument("--token", help="optional bearer token to require")
    _add_common(svp)

    np = sub.add_parser("init", help="write a sample config file")
    np.add_argument("-o", "--output", default="asm.config.json")

    return p


def _load_config(args) -> Config:
    cfg = Config.load(getattr(args, "config", None))
    return cfg.merge_args(args)


def cmd_scan(args) -> int:
    cfg = _load_config(args)
    run_pass(args.target, cfg)
    return 0


def cmd_watch(args) -> int:
    cfg = _load_config(args)
    interval = max(1, args.interval) * 60
    print(f"[+] Watching {args.target} every {args.interval} min "
          f"(Ctrl-C to stop). For production, prefer a cron job.")
    try:
        while True:
            run_pass(args.target, cfg)
            print(f"[*] Sleeping {args.interval} min until next pass …")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    return 0


def cmd_ingest(args) -> int:
    cfg = _load_config(args)
    store = Store(cfg.db)
    try:
        scan_id = store.start_scan(args.target, results_dir=args.results_dir)
        result = ingest_results(args.target, args.results_dir)
        if cfg.intel_enrich and result.findings:
            from .intel import Enricher
            cache = Path(cfg.intel_cache_dir) if cfg.intel_cache_dir else None
            Enricher(cache_dir=cache, offline=cfg.intel_offline).enrich(
                result.findings)
        if result.findings:
            from .attack import annotate
            annotate(result.findings)
        for tag in (cfg.criticality or []):
            if tag.get("pattern"):
                store.set_tag(args.target, tag["pattern"],
                              criticality=tag.get("criticality", 3),
                              kind=tag.get("kind"), sensitivity=tag.get("sensitivity"),
                              note=tag.get("note"))
        changes = store.record_result(scan_id, result)
        store.apply_business_risk(scan_id)
        print(f"[✓] Ingested {len(result.assets)} assets, "
              f"{len(result.findings)} findings, {len(changes)} changes "
              f"(scan #{scan_id})")
    finally:
        store.close()
    return 0


def cmd_targets(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.list_targets()
        if not rows:
            print("No targets tracked yet.")
            return 0
        print(f"{'TARGET':40} {'SCANS':>6} {'ASSETS':>8}  CREATED")
        for r in rows:
            print(f"{r['name']:40} {r['scans']:>6} {r['active_assets']:>8}  "
                  f"{r['created_at']}")
    finally:
        store.close()
    return 0


def cmd_assets(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.assets(args.target, kind=args.kind,
                            active_only=not args.all)
        for r in rows:
            flag = "" if r["active"] else " (inactive)"
            print(f"[{r['kind']}] {r['key']}{flag}")
        print(f"\n{len(rows)} assets")
    finally:
        store.close()
    return 0


def cmd_findings(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.findings(args.target, status=args.status,
                             min_severity=args.min_severity)
        if rows:
            print(f"{'BRISK':>5} {'RISK':>5}  {'SEV':8} {'KEV':3} {'EPSS':>5}  "
                  f"{'CVE':16} {'ATT&CK':16} NAME @ LOCATION")
            print("-" * 110)
        for r in rows:
            epss = f"{r['epss']:.2f}" if r["epss"] is not None else "  -  "
            kev = "KEV" if r["kev"] else " - "
            cve = r["cve"] or ""
            attack = (r["attack_techniques"] or "")[:16]
            print(f"{(r['business_risk'] or 0):>5.1f} {(r['risk_score'] or 0):>5.1f}  "
                  f"{(r['severity'] or 'unknown').upper():8} {kev:3} {epss:>5}  "
                  f"{cve:16} {attack:16} {r['name']} @ {r['matched_at']}")
        print(f"\n{len(rows)} findings (sorted by business risk)")
    finally:
        store.close()
    return 0


def cmd_intel_update(args) -> int:
    from .intel import Enricher
    cfg = _load_config(args)
    cache = Path(cfg.intel_cache_dir) if cfg.intel_cache_dir else None
    stats = Enricher(cache_dir=cache, offline=False).refresh_feeds()
    print(f"[✓] KEV cache refreshed: {stats.get('kev_entries', 0)} entries")
    return 0


def cmd_changes(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.changes_since(args.target, limit=args.limit)
        for r in rows:
            print(f"{r['created_at']}  {r['change_type']:18} {r['subject']}")
        print(f"\n{len(rows)} changes")
    finally:
        store.close()
    return 0


def cmd_report(args) -> int:
    cfg = _load_config(args)
    store = Store(cfg.db)
    try:
        out = args.output or f"{args.target}_asm_report.html"
        path = build_asm_report(store, args.target, out)
        print(f"[✓] Report written: {path}")
    finally:
        store.close()
    return 0


def cmd_init(args) -> int:
    out = Path(args.output)
    if out.exists():
        print(f"[!] {out} already exists; not overwriting.")
        return 1
    out.write_text(Config().to_json())
    print(f"[✓] Sample config written: {out}")
    return 0


def cmd_tag(args) -> int:
    store = Store(_load_config(args).db)
    try:
        store.set_tag(args.target, args.pattern, criticality=args.criticality,
                      kind=args.kind, sensitivity=args.sensitivity, note=args.note)
        print(f"[✓] Tagged {args.pattern} criticality={args.criticality} "
              f"for {args.target}")
    finally:
        store.close()
    return 0


def cmd_tags(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.list_tags(args.target)
        for r in rows:
            print(f"crit={r['criticality']}  {r['pattern']:40} "
                  f"{(r['sensitivity'] or ''):10} {r['note'] or ''}")
        print(f"\n{len(rows)} tags")
    finally:
        store.close()
    return 0


def cmd_graph(args) -> int:
    from .graph import build_graph, graph_html
    store = Store(_load_config(args).db)
    try:
        data = build_graph(store, args.target)
        if args.html:
            out = args.output or f"{args.target}_graph.html"
            Path(out).write_text(graph_html(data, args.target))
        else:
            out = args.output or f"{args.target}_graph.json"
            Path(out).write_text(json.dumps(data, indent=2))
        print(f"[✓] Graph written: {out} "
              f"({len(data['nodes'])} nodes, {len(data['edges'])} edges)")
    finally:
        store.close()
    return 0


def cmd_export(args) -> int:
    store = Store(_load_config(args).db)
    try:
        rows = store.findings(args.target, status="open")
        cols = ["business_risk", "risk_score", "severity", "kev", "epss", "cve",
                "attack_techniques", "name", "matched_at", "status", "first_seen_at"]
        if args.format == "csv":
            import csv
            out = args.output or f"{args.target}_findings.csv"
            with open(out, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                for r in rows:
                    w.writerow([r[c] for c in cols])
        else:
            out = args.output or f"{args.target}_findings.json"
            Path(out).write_text(json.dumps(
                [{c: r[c] for c in cols} for r in rows], indent=2))
        print(f"[✓] Exported {len(rows)} findings: {out}")
    finally:
        store.close()
    return 0


def cmd_appscan(args) -> int:
    from .appscan import scan_app, to_scan_result
    cfg = _load_config(args)
    paths = (args.apk or []) + (args.ipa or [])
    if not paths:
        print("[!] provide at least one --apk or --ipa file")
        return 1
    store = Store(cfg.db)
    try:
        total_secrets = total_subs = 0
        combined = {}
        for path in paths:
            print(f"[+] Analysing {path}")
            scan = scan_app(path, target=args.target)
            if scan.get("error"):
                print(f"[!] {path}: {scan['error']}")
                continue
            combined[path] = scan
            result = to_scan_result(scan, args.target)
            if cfg.intel_enrich and result.findings:
                from .intel import Enricher
                cache = Path(cfg.intel_cache_dir) if cfg.intel_cache_dir else None
                Enricher(cache_dir=cache, offline=cfg.intel_offline).enrich(
                    result.findings)
            from .attack import annotate
            annotate(result.findings)
            scan_id = store.start_scan(args.target, results_dir=f"appscan:{path}")
            store.record_result(scan_id, result)
            store.apply_business_risk(scan_id)
            total_secrets += len(scan.get("secrets", []))
            total_subs += len(scan.get("subdomains", []))
            print(f"    secrets={len(scan.get('secrets', []))} "
                  f"buckets={len(scan.get('buckets', []))} "
                  f"subdomains={len(scan.get('subdomains', []))} "
                  f"urls={len(scan.get('urls', []))} "
                  f"trackers={len(scan.get('trackers', []))}")
        print(f"\n[✓] App scan complete: {total_secrets} secrets, "
              f"{total_subs} in-scope subdomains folded into {args.target}")
        if args.out:
            Path(args.out).write_text(json.dumps(combined, indent=2))
            print(f"[✓] BeVigil-style JSON written: {args.out}")
    finally:
        store.close()
    return 0


def cmd_codescan(args) -> int:
    from .codescan import scan_github, to_scan_result
    cfg = _load_config(args)
    store = Store(cfg.db)
    try:
        scan = scan_github(args.target, token=args.github_token, org=args.org,
                           max_files=args.max_files)
        if scan.get("error"):
            print(f"[!] {scan['error']}")
            return 1
        result = to_scan_result(scan, args.target)
        if cfg.intel_enrich and result.findings:
            from .intel import Enricher
            cache = Path(cfg.intel_cache_dir) if cfg.intel_cache_dir else None
            Enricher(cache_dir=cache, offline=cfg.intel_offline).enrich(result.findings)
        from .attack import annotate
        annotate(result.findings)
        scan_id = store.start_scan(args.target, results_dir="codescan:github")
        store.record_result(scan_id, result)
        store.apply_business_risk(scan_id)
        print(f"[✓] Code-leak scan: {len(scan.get('secrets', []))} secrets, "
              f"{len(scan.get('subdomains', []))} subdomains across "
              f"{len(scan.get('files', []))} files")
        if args.out:
            Path(args.out).write_text(json.dumps(scan, indent=2))
            print(f"[✓] JSON written: {args.out}")
    finally:
        store.close()
    return 0


def cmd_serve(args) -> int:
    from .webapp import run_server  # pure stdlib, no extra deps
    cfg = _load_config(args)
    run_server(cfg, host=args.host, port=args.port, token=args.token,
               config_path=getattr(args, "config", None))
    return 0


_DISPATCH = {
    "scan": cmd_scan,
    "watch": cmd_watch,
    "ingest": cmd_ingest,
    "targets": cmd_targets,
    "assets": cmd_assets,
    "findings": cmd_findings,
    "changes": cmd_changes,
    "report": cmd_report,
    "intel-update": cmd_intel_update,
    "tag": cmd_tag,
    "tags": cmd_tags,
    "graph": cmd_graph,
    "export": cmd_export,
    "appscan": cmd_appscan,
    "codescan": cmd_codescan,
    "serve": cmd_serve,
    "init": cmd_init,
}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("-h", "--help"):
        # Banner to stderr keeps stdout clean for piping/parsing.
        print(BANNER, file=sys.stderr)
    args = build_parser().parse_args(argv)
    return _DISPATCH[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
