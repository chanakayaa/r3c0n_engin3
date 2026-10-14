"""
Web UI for ReconEngine ASM (FastAPI + uvicorn).

Start, watch and download scans from a browser:
  * dashboard of tracked targets + running jobs
  * start-scan form (runs a pass as a background subprocess)
  * live job status + log tail
  * per-target findings (by business risk), assets, changes, ATT&CK
  * downloadable HTML report, interactive asset graph, JSON/CSV export

Runs the scan as `python -m asm scan ...` subprocesses so the UI stays
responsive and each job's output is captured to its own log file. Binds to
localhost by default. It can initiate active scans - do not expose it, and use
only against authorized targets.

Requires the optional extra:  pip install '.[web]'
"""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

try:
    from fastapi import FastAPI, Form, HTTPException, Request
    from fastapi.responses import (HTMLResponse, JSONResponse, FileResponse,
                                   RedirectResponse, PlainTextResponse)
except ImportError as exc:  # surfaced nicely by cli.cmd_serve
    raise ImportError("fastapi is required for the web UI") from exc

from .config import Config
from .graph import build_graph, graph_html
from .report import build_asm_report
from .store import Store

# ----------------------------------------------------------------------------
# Shared state (set by run_server before uvicorn starts)
# ----------------------------------------------------------------------------

_STATE: Dict[str, object] = {"db": "asm.db", "token": None, "config_path": None,
                             "runs_dir": Path(".asm_runs")}
_JOBS: Dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()

CSS = """
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f172a;
color:#e5e7eb;margin:0;padding:24px;}
a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}
h1,h2{color:#38bdf8;} h1{margin-top:0;}
.banner{background:#422006;color:#fde68a;padding:8px 14px;border-radius:8px;
margin-bottom:16px;font-size:13px;}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0;}
.card{background:#1e293b;border-radius:10px;padding:14px 18px;min-width:120px;}
.card .n{font-size:26px;font-weight:700;} .card .l{color:#94a3b8;font-size:13px;}
table{border-collapse:collapse;width:100%;margin:10px 0;background:#020617;
border-radius:8px;overflow:hidden;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1e293b;font-size:14px;}
th{background:#1e293b;color:#cbd5e1;}
form{background:#1e293b;border-radius:10px;padding:16px;margin:14px 0;}
label{display:inline-block;margin:6px 12px 6px 0;font-size:14px;}
input[type=text]{background:#020617;border:1px solid #334155;color:#e5e7eb;
padding:7px 10px;border-radius:6px;min-width:260px;}
button{background:#0369a1;color:#fff;border:0;padding:9px 16px;border-radius:6px;
cursor:pointer;font-weight:600;} button:hover{background:#0284c7;}
.sev{font-weight:700;padding:2px 8px;border-radius:6px;font-size:12px;}
.critical{background:#7f1d1d;color:#fecaca;} .high{background:#9a3412;color:#fed7aa;}
.medium{background:#854d0e;color:#fde68a;} .low{background:#1e3a8a;color:#bfdbfe;}
.info,.unknown{background:#334155;color:#cbd5e1;}
.muted{color:#94a3b8;font-size:13px;} pre{background:#000;color:#9ae6b4;padding:10px;
border-radius:6px;overflow:auto;max-height:460px;}
.pill{background:#334155;border-radius:10px;padding:1px 7px;font-size:11px;}
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _page(title: str, body: str) -> str:
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{_esc(title)}</title><style>{CSS}</style></head><body>"
            f"<div class='banner'>⚠ ASM console — initiates active scans; "
            f"authorized targets only. Keep bound to localhost.</div>"
            f"{body}</body></html>")


def _sev_badge(sev: str) -> str:
    sev = (sev or "unknown").lower()
    return f"<span class='sev {sev}'>{_esc(sev)}</span>"


# ----------------------------------------------------------------------------
# Background job management
# ----------------------------------------------------------------------------

def _runs_dir() -> Path:
    d = Path(_STATE["runs_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def start_job(target: str, opts: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    log_path = _runs_dir() / f"{job_id}.log"
    cmd = [sys.executable, "-m", "asm", "scan", "-t", target,
           "--db", str(_STATE["db"])]
    if _STATE.get("config_path"):
        cmd += ["--config", str(_STATE["config_path"])]
    if opts.get("crawl"):
        cmd.append("--crawl")
    if opts.get("dirs"):
        cmd.append("--dirs")
    if opts.get("no_vuln"):
        cmd.append("--no-vuln")
    if opts.get("offline"):
        cmd.append("--offline")
    if opts.get("severity"):
        cmd += ["--severity", opts["severity"]]

    logf = open(log_path, "w")
    # New process group so the scan is isolated from the server process.
    proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                            cwd=os.getcwd())
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "id": job_id, "target": target, "proc": proc, "logf": logf,
            "log_path": str(log_path), "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cmd": " ".join(cmd),
        }
    return job_id


def _job_status(job: dict) -> str:
    proc = job.get("proc")
    if proc is None:
        return "unknown"
    rc = proc.poll()
    if rc is None:
        return "running"
    return "completed" if rc == 0 else "failed"


def _job_view(job: dict) -> dict:
    status = _job_status(job)
    tail = ""
    try:
        tail = Path(job["log_path"]).read_text(errors="ignore")[-6000:]
    except OSError:
        pass
    return {"id": job["id"], "target": job["target"], "status": status,
            "started": job["started"], "log": tail}


# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------

app = FastAPI(title="ReconEngine ASM")


@app.middleware("http")
async def _auth(request: Request, call_next):
    token = _STATE.get("token")
    if token:
        supplied = (request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                    or request.query_params.get("token", ""))
        if supplied != token:
            return PlainTextResponse("unauthorized", status_code=401)
    return await call_next(request)


def _store() -> Store:
    return Store(str(_STATE["db"]))


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    store = _store()
    try:
        targets = store.list_targets()
    finally:
        store.close()
    with _JOBS_LOCK:
        jobs = [_job_view(j) for j in _JOBS.values()]
    jobs.sort(key=lambda j: j["started"], reverse=True)

    rows = "".join(
        f"<tr><td><a href='/targets/{_esc(t['name'])}'>{_esc(t['name'])}</a></td>"
        f"<td>{t['scans']}</td><td>{t['active_assets']}</td></tr>"
        for t in targets) or "<tr><td colspan=3 class='muted'>No targets yet.</td></tr>"

    job_rows = "".join(
        f"<tr><td><a href='/jobs/{j['id']}'>{j['id']}</a></td>"
        f"<td>{_esc(j['target'])}</td><td>{_esc(j['status'])}</td>"
        f"<td class='muted'>{_esc(j['started'])}</td></tr>"
        for j in jobs[:15]) or "<tr><td colspan=4 class='muted'>No jobs this session.</td></tr>"

    body = f"""
    <h1>ReconEngine ASM</h1>
    <form method='post' action='/scan'>
      <label>Target <input type='text' name='target' placeholder='example.com' required></label>
      <label>Severity <input type='text' name='severity' placeholder='critical,high,medium,low'></label><br>
      <label><input type='checkbox' name='crawl'> crawl</label>
      <label><input type='checkbox' name='dirs'> dirs</label>
      <label><input type='checkbox' name='no_vuln'> skip vuln scan</label>
      <label><input type='checkbox' name='offline'> offline intel</label>
      <button type='submit'>Start scan</button>
    </form>
    <h2>Running / recent jobs</h2>
    <table><tr><th>Job</th><th>Target</th><th>Status</th><th>Started</th></tr>{job_rows}</table>
    <h2>Tracked targets</h2>
    <table><tr><th>Target</th><th>Scans</th><th>Active assets</th></tr>{rows}</table>
    """
    return _page("ASM console", body)


@app.post("/scan")
def scan(target: str = Form(...), severity: str = Form(""),
         crawl: str = Form(None), dirs: str = Form(None),
         no_vuln: str = Form(None), offline: str = Form(None)):
    target = target.strip()
    if not target:
        raise HTTPException(400, "target required")
    job_id = start_job(target, {
        "severity": severity.strip(), "crawl": bool(crawl), "dirs": bool(dirs),
        "no_vuln": bool(no_vuln), "offline": bool(offline),
    })
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    return JSONResponse(_job_view(job))


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(job_id: str) -> str:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    v = _job_view(job)
    done = v["status"] in ("completed", "failed")
    refresh = "" if done else "<meta http-equiv='refresh' content='3'>"
    link = (f"<p><a href='/targets/{_esc(v['target'])}'>→ View results for "
            f"{_esc(v['target'])}</a></p>" if done else "")
    body = f"""{refresh}
    <h1>Job {_esc(v['id'])} — {_esc(v['target'])}</h1>
    <p>Status: <span class='pill'>{_esc(v['status'])}</span>
       started {_esc(v['started'])} · <a href='/'>dashboard</a></p>
    {link}
    <h2>Log</h2><pre>{_esc(v['log']) or '(waiting for output...)'}</pre>
    """
    return _page(f"Job {v['id']}", body)


@app.get("/targets/{target}", response_class=HTMLResponse)
def target_page(target: str) -> str:
    store = _store()
    try:
        findings = store.findings(target, status="open")
        assets = store.assets(target, active_only=True)
        changes = store.changes_since(target, limit=40)
        latest = store.latest_scan(target)
    finally:
        store.close()

    frows = "".join(
        f"<tr><td><b>{(f['business_risk'] or 0):.1f}</b></td>"
        f"<td>{(f['risk_score'] or 0):.1f}</td><td>{_sev_badge(f['severity'])}</td>"
        f"<td>{'KEV' if f['kev'] else ''}</td>"
        f"<td>{(f['epss'] if f['epss'] is not None else '')}</td>"
        f"<td>{_esc(f['cve'])}</td><td>{_esc(f['attack_techniques'])}</td>"
        f"<td>{_esc(f['name'])}</td><td class='muted'>{_esc(f['matched_at'])}</td></tr>"
        for f in findings) or "<tr><td colspan=9 class='muted'>No open findings.</td></tr>"

    arows = "".join(
        f"<tr><td class='pill'>{_esc(a['kind'])}</td><td>{_esc(a['key'])}</td></tr>"
        for a in assets[:500]) or "<tr><td colspan=2 class='muted'>No assets.</td></tr>"

    crows = "".join(
        f"<tr><td class='muted'>{_esc(c['created_at'])}</td>"
        f"<td>{_esc(c['change_type'])}</td><td>{_esc(c['subject'])}</td></tr>"
        for c in changes) or "<tr><td colspan=3 class='muted'>No changes.</td></tr>"

    scanned = f"last scan #{latest['id']} at {latest['finished_at']}" if latest else "no completed scans"
    body = f"""
    <p><a href='/'>← dashboard</a></p>
    <h1>{_esc(target)}</h1>
    <p class='muted'>{_esc(scanned)}</p>
    <div class='cards'>
      <div class='card'><div class='n'>{len(assets)}</div><div class='l'>assets</div></div>
      <div class='card'><div class='n'>{len(findings)}</div><div class='l'>open findings</div></div>
    </div>
    <p><a href='/targets/{_esc(target)}/report'>⬇ Download HTML report</a> ·
       <a href='/targets/{_esc(target)}/graph'>\U0001f578 Asset graph</a> ·
       <a href='/targets/{_esc(target)}/export.json'>export JSON</a> ·
       <a href='/targets/{_esc(target)}/export.csv'>export CSV</a></p>
    <h2>Findings (by business risk)</h2>
    <table><tr><th>BRisk</th><th>Risk</th><th>Sev</th><th>KEV</th><th>EPSS</th>
    <th>CVE</th><th>ATT&amp;CK</th><th>Name</th><th>Location</th></tr>{frows}</table>
    <h2>Assets</h2><table><tr><th>Kind</th><th>Asset</th></tr>{arows}</table>
    <h2>Recent changes</h2>
    <table><tr><th>When</th><th>Type</th><th>Subject</th></tr>{crows}</table>
    """
    return _page(target, body)


@app.get("/targets/{target}/report")
def target_report(target: str):
    store = _store()
    try:
        out = _runs_dir() / f"{target}_report.html"
        build_asm_report(store, target, str(out))
    finally:
        store.close()
    return FileResponse(str(out), media_type="text/html",
                        filename=f"{target}_asm_report.html")


@app.get("/api/targets/{target}/graph.json")
def target_graph_json(target: str):
    store = _store()
    try:
        return JSONResponse(build_graph(store, target))
    finally:
        store.close()


@app.get("/targets/{target}/graph", response_class=HTMLResponse)
def target_graph(target: str) -> str:
    store = _store()
    try:
        return graph_html(build_graph(store, target), target)
    finally:
        store.close()


@app.get("/targets/{target}/export.json")
def export_json(target: str):
    store = _store()
    try:
        rows = store.findings(target, status="open")
        cols = ["business_risk", "risk_score", "severity", "kev", "epss", "cve",
                "attack_techniques", "name", "matched_at", "first_seen_at"]
        data = [{c: r[c] for c in cols} for r in rows]
    finally:
        store.close()
    return JSONResponse(data)


@app.get("/targets/{target}/export.csv")
def export_csv(target: str):
    import csv
    import io
    store = _store()
    try:
        rows = store.findings(target, status="open")
    finally:
        store.close()
    cols = ["business_risk", "risk_score", "severity", "kev", "epss", "cve",
            "attack_techniques", "name", "matched_at", "first_seen_at"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([r[c] for c in cols])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


def run_server(config: Config, host: str = "127.0.0.1", port: int = 8000,
               token: Optional[str] = None,
               config_path: Optional[str] = None) -> None:
    import uvicorn
    _STATE["db"] = config.db
    _STATE["token"] = token
    _STATE["config_path"] = config_path
    _STATE["runs_dir"] = Path(config.db).resolve().parent / ".asm_runs"
    print(f"[+] ASM web UI on http://{host}:{port}  (db={config.db})")
    if host not in ("127.0.0.1", "localhost"):
        print("[!] Binding to a non-local address. This UI starts scans — "
              "protect it with --token and a firewall.")
    if token:
        print("[+] Bearer token required (pass ?token=... or Authorization header)")
    uvicorn.run(app, host=host, port=port, log_level="info")
