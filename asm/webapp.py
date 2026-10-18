"""
Web UI for ReconEngine ASM — pure standard library (no FastAPI/uvicorn).

Runs on any Python 3.9+ with zero pip installs: `asm serve`. Launch and watch
every scan type from the browser:

  * Recon    — full recon + vuln pass against a domain
  * App      — static APK/IPA secret/asset scan (server-side file path)
  * Code     — public GitHub code-leak scan

plus prioritised findings, the asset graph, downloadable reports and JSON/CSV
export. Scans run as background subprocesses (`python -m asm <kind> …`), so the
UI stays responsive and each job streams to its own log.

Bind to localhost (default). It initiates active scans — do not expose it, and
use only against authorized targets.
"""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional

from .config import Config
from .graph import build_graph, graph_html
from .report import build_asm_report
from .store import Store

_STATE: Dict[str, object] = {"db": "asm.db", "token": None,
                             "config_path": None, "runs_dir": Path(".asm_runs")}
_JOBS: Dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# Look & feel (inline, offline-safe) — gradients, entrance/hover motion,
# pulsing status, animated bars, count-up KPIs, live log.
# --------------------------------------------------------------------------- #
CSS = """
:root{--bg:#0b1220;--panel:#111c30;--panel2:#0d1626;--line:#1e2d45;
--fg:#e6edf6;--muted:#8aa0bd;--accent:#38bdf8;--accent2:#818cf8;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
background:radial-gradient(1200px 600px at 20% -10%,#15233c 0%,var(--bg) 55%);
color:var(--fg);min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:22px}
.top{display:flex;align-items:center;gap:14px;animation:fadeDown .5s ease both}
.logo{font-weight:800;font-size:22px;letter-spacing:.3px;
background:linear-gradient(90deg,var(--accent),var(--accent2),#f472b6);
-webkit-background-clip:text;background-clip:text;color:transparent;
background-size:200% auto;animation:shine 6s linear infinite}
.sub{color:var(--muted);font-size:12px}
.banner{margin:14px 0;padding:9px 14px;border-radius:10px;font-size:12.5px;
background:linear-gradient(90deg,#3b1d06,#2a1604);color:#fde3b0;
border:1px solid #5a3410;animation:fadeUp .5s .05s ease both}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));
border:1px solid var(--line);border-radius:16px;padding:18px;margin:16px 0;
box-shadow:0 10px 30px rgba(0,0,0,.25);animation:fadeUp .55s ease both}
.card:nth-child(2){animation-delay:.05s}.card:nth-child(3){animation-delay:.1s}
h1{margin:.2em 0}h2{color:var(--accent);margin:0 0 10px;font-size:18px}
.kpis{display:flex;flex-wrap:wrap;gap:12px}
.kpi{flex:1;min-width:120px;background:#0a1322;border:1px solid var(--line);
border-radius:14px;padding:14px 16px;transition:transform .2s,box-shadow .2s}
.kpi:hover{transform:translateY(-3px);box-shadow:0 10px 24px rgba(56,189,248,.14)}
.kpi .n{font-size:30px;font-weight:800}.kpi .l{color:var(--muted);font-size:12px}
.tabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.tab{padding:9px 16px;border-radius:10px;cursor:pointer;color:var(--muted);
background:#0a1322;border:1px solid var(--line);transition:.2s;font-weight:600}
.tab:hover{color:var(--fg)}.tab.active{color:#07131f;
background:linear-gradient(90deg,var(--accent),var(--accent2));border-color:transparent}
.pane{display:none;animation:fadeUp .4s ease both}.pane.active{display:block}
label{display:block;color:var(--muted);font-size:12px;margin:10px 0 4px}
input[type=text],input[type=password]{width:100%;background:#07101d;
border:1px solid var(--line);color:var(--fg);padding:11px 12px;border-radius:10px;
transition:border-color .2s,box-shadow .2s}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
.row{display:flex;gap:16px;flex-wrap:wrap}.row>div{flex:1;min-width:220px}
.checks{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0;color:var(--muted);font-size:13px}
.checks label{display:inline-flex;align-items:center;gap:7px;margin:0;cursor:pointer}
button{margin-top:14px;background:linear-gradient(90deg,var(--accent),var(--accent2));
color:#07131f;border:0;padding:12px 20px;border-radius:11px;font-weight:800;
cursor:pointer;transition:transform .12s,filter .2s;background-size:160% auto}
button:hover{filter:brightness(1.08);transform:translateY(-1px);background-position:right center}
button:active{transform:translateY(0)}
table{border-collapse:collapse;width:100%;background:#07101d;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);font-size:13.5px}
th{background:#0d1a2e;color:#b9cbe4;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
tr{transition:background .15s}tbody tr:hover{background:#0c1830}
.sev{font-weight:800;padding:2px 9px;border-radius:7px;font-size:11px}
.critical{background:#7f1d1d;color:#fecaca}.high{background:#9a3412;color:#fed7aa}
.medium{background:#854d0e;color:#fde68a}.low{background:#1e3a8a;color:#bfdbfe}
.info,.unknown{background:#334155;color:#cbd5e1}
.bar{height:7px;border-radius:6px;background:#0d1a2e;overflow:hidden;min-width:70px}
.bar>i{display:block;height:100%;border-radius:6px;
background:linear-gradient(90deg,#f472b6,#fb923c,#38bdf8);width:0;animation:grow 1s ease forwards}
.pill{display:inline-block;background:#12233c;border:1px solid var(--line);
border-radius:999px;padding:2px 10px;font-size:11px;color:#b9cbe4}
.badge{display:inline-flex;align-items:center;gap:7px;padding:4px 12px;border-radius:999px;
font-weight:700;font-size:12px}
.badge.run{background:#0b2b3a;color:#7dd3fc}
.badge.run .dot{width:8px;height:8px;border-radius:50%;background:#38bdf8;animation:pulse 1.1s infinite}
.badge.ok{background:#07301f;color:#6ee7b7}.badge.fail{background:#3b0d12;color:#fca5a5}
.spinner{width:16px;height:16px;border:2px solid #1e3a5f;border-top-color:var(--accent);
border-radius:50%;display:inline-block;animation:spin .8s linear infinite;vertical-align:middle}
pre{background:#060c16;color:#8ef0b8;padding:14px;border-radius:12px;overflow:auto;
max-height:480px;font-size:12.5px;line-height:1.5;border:1px solid var(--line)}
.muted{color:var(--muted);font-size:13px}
.toast{position:fixed;right:18px;bottom:18px;background:#0b2b3a;color:#7dd3fc;
padding:12px 18px;border-radius:12px;border:1px solid #155e75;animation:fadeUp .4s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes fadeDown{from{opacity:0;transform:translateY(-14px)}to{opacity:1;transform:none}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.7)}}
@keyframes shine{to{background-position:200% center}}
@keyframes grow{from{width:0}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

JS = """
function tab(id,el){document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'));
document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
document.getElementById(id).classList.add('active');el.classList.add('active');}
function countUp(){document.querySelectorAll('.kpi .n').forEach(n=>{
 const t=+n.dataset.v||0;if(!t){n.textContent='0';return;}let c=0;const step=Math.max(1,t/28);
 const id=setInterval(()=>{c+=step;if(c>=t){c=t;clearInterval(id);}n.textContent=Math.round(c);},22);});}
document.addEventListener('DOMContentLoaded',countUp);
function toast(m){const d=document.createElement('div');d.className='toast';d.textContent=m;
document.body.appendChild(d);setTimeout(()=>d.remove(),2600);}
function pollJob(id){const log=document.getElementById('log'),b=document.getElementById('jbadge');
async function tick(){try{const r=await fetch('/api/jobs/'+id+location.search);const j=await r.json();
 if(log){const atBottom=log.scrollTop+log.clientHeight>=log.scrollHeight-40;
  log.textContent=j.log||'(waiting for output…)';if(atBottom)log.scrollTop=log.scrollHeight;}
 if(b){b.className='badge '+(j.status==='running'?'run':(j.status==='completed'?'ok':'fail'));
  b.innerHTML=(j.status==='running'?'<span class=dot></span>':'')+j.status;}
 if(j.status!=='running'){document.getElementById('spin')?.remove();
  const link=document.getElementById('resultlink');if(link)link.style.display='inline';return;}
 }catch(e){}setTimeout(tick,2000);}tick();}
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _sev(s) -> str:
    s = (s or "unknown").lower()
    return f"<span class='sev {s}'>{_esc(s)}</span>"


def _page(title: str, body: str, onload: str = "") -> str:
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)}</title><style>{CSS}</style></head><body>"
            f"<div class='wrap'><div class='top'><div class='logo'>◉ ReconEngine ASM</div>"
            f"<div class='sub'>Attack Surface Monitoring</div></div>"
            f"<div class='banner'>⚠ Initiates active scans — authorized targets only; keep on localhost.</div>"
            f"{body}</div><script>{JS}</script>"
            f"<script>{onload}</script></body></html>")


# --------------------------------------------------------------------------- #
# Background jobs
# --------------------------------------------------------------------------- #

def _runs_dir() -> Path:
    d = Path(_STATE["runs_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def start_job(kind: str, target: str, opts: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    log_path = _runs_dir() / f"{job_id}.log"
    cmd = [sys.executable, "-m", "asm", kind, "-t", target,
           "--db", str(_STATE["db"])]
    if _STATE.get("config_path"):
        cmd += ["--config", str(_STATE["config_path"])]
    for flag in ("crawl", "dirs", "no_vuln", "offline"):
        if opts.get(flag):
            cmd.append("--" + flag.replace("_", "-"))
    if opts.get("severity"):
        cmd += ["--severity", opts["severity"]]
    if kind == "appscan" and opts.get("apk"):
        cmd += ["--apk", opts["apk"]]
    if kind == "codescan":
        if opts.get("org"):
            cmd += ["--org", opts["org"]]
        if opts.get("github_token"):
            cmd += ["--github-token", opts["github_token"]]
    logf = open(log_path, "w")
    proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                            cwd=os.getcwd())
    with _JOBS_LOCK:
        _JOBS[job_id] = {"id": job_id, "kind": kind, "target": target,
                         "proc": proc, "log_path": str(log_path),
                         "started": time.strftime("%H:%M:%S")}
    return job_id


def _job_view(job: dict) -> dict:
    proc = job.get("proc")
    status = "running" if proc.poll() is None else (
        "completed" if proc.returncode == 0 else "failed")
    try:
        tail = Path(job["log_path"]).read_text(errors="ignore")[-6000:]
    except OSError:
        tail = ""
    return {"id": job["id"], "kind": job["kind"], "target": job["target"],
            "status": status, "started": job["started"], "log": tail}


def _store() -> Store:
    return Store(str(_STATE["db"]))


# --------------------------------------------------------------------------- #
# Page renderers
# --------------------------------------------------------------------------- #

def render_dashboard() -> str:
    store = _store()
    try:
        targets = store.list_targets()
    finally:
        store.close()
    with _JOBS_LOCK:
        jobs = sorted((_job_view(j) for j in _JOBS.values()),
                      key=lambda j: j["started"], reverse=True)

    trows = "".join(
        f"<tr><td><a href='/targets/{_esc(t['name'])}{{q}}'>{_esc(t['name'])}</a></td>"
        f"<td>{t['scans']}</td><td>{t['active_assets']}</td></tr>"
        for t in targets) or "<tr><td colspan=3 class='muted'>No targets yet — run a scan.</td></tr>"
    jrows = "".join(
        f"<tr><td><a href='/jobs/{j['id']}{{q}}'>{j['id']}</a></td>"
        f"<td><span class='pill'>{_esc(j['kind'])}</span></td><td>{_esc(j['target'])}</td>"
        f"<td>{_badge(j['status'])}</td><td class='muted'>{_esc(j['started'])}</td></tr>"
        for j in jobs[:12]) or "<tr><td colspan=5 class='muted'>No jobs this session.</td></tr>"

    body = f"""
    <div class='card'>
      <div class='tabs'>
        <div class='tab active' onclick="tab('p-recon',this)">\U0001f50e Recon</div>
        <div class='tab' onclick="tab('p-app',this)">\U0001f4f1 App (APK/IPA)</div>
        <div class='tab' onclick="tab('p-code',this)">\U0001f9ec Code leaks</div>
      </div>
      <div id='p-recon' class='pane active'>
        <form method='post' action='/scan{{q}}' onsubmit="toast('Recon scan queued…')">
          <div class='row'><div><label>Target domain</label>
            <input type='text' name='target' placeholder='example.com' required></div>
          <div><label>Severities</label>
            <input type='text' name='severity' placeholder='critical,high,medium,low'></div></div>
          <div class='checks'>
            <label><input type='checkbox' name='crawl'> crawl</label>
            <label><input type='checkbox' name='dirs'> dirs</label>
            <label><input type='checkbox' name='no_vuln'> skip vuln</label>
            <label><input type='checkbox' name='offline'> offline intel</label></div>
          <button>Start recon scan</button>
        </form>
      </div>
      <div id='p-app' class='pane'>
        <form method='post' action='/appscan{{q}}' onsubmit="toast('App scan queued…')">
          <div class='row'><div><label>Target domain (to fold assets into)</label>
            <input type='text' name='target' placeholder='example.com' required></div>
          <div><label>APK/IPA path on this machine</label>
            <input type='text' name='apk' placeholder='/path/to/app-release.apk' required></div></div>
          <div class='checks'><label><input type='checkbox' name='offline' checked> offline intel</label></div>
          <button>Scan app</button>
        </form>
        <p class='muted'>Static analysis of a local APK/IPA — hardcoded secrets, cloud buckets, hidden subdomains.</p>
      </div>
      <div id='p-code' class='pane'>
        <form method='post' action='/codescan{{q}}' onsubmit="toast('Code-leak scan queued…')">
          <div class='row'><div><label>Target domain</label>
            <input type='text' name='target' placeholder='example.com' required></div>
          <div><label>GitHub org (optional)</label>
            <input type='text' name='org' placeholder='acme'></div></div>
          <label>GitHub token (or set GITHUB_TOKEN on the server)</label>
          <input type='password' name='github_token' placeholder='ghp_…'>
          <button>Scan public code</button>
        </form>
        <p class='muted'>Searches public GitHub code for leaked secrets &amp; back-end subdomains.</p>
      </div>
    </div>
    <div class='card'><h2>Running / recent jobs</h2>
      <table><tr><th>Job</th><th>Type</th><th>Target</th><th>Status</th><th>Started</th></tr>{jrows}</table></div>
    <div class='card'><h2>Tracked targets</h2>
      <table><tr><th>Target</th><th>Scans</th><th>Assets</th></tr>{trows}</table></div>
    """
    return _page("ASM console", body)


def _badge(status: str) -> str:
    cls = {"running": "run", "completed": "ok", "failed": "fail"}.get(status, "")
    dot = "<span class='dot'></span>" if status == "running" else ""
    return f"<span class='badge {cls}'>{dot}{_esc(status)}</span>"


def render_job(job_id: str) -> Optional[str]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        return None
    v = _job_view(job)
    spin = "" if v["status"] != "running" else "<span id='spin' class='spinner'></span> "
    body = f"""
    <div class='card'>
      <h1>{spin}{_esc(v['kind'])} job <span class='muted'>{_esc(v['id'])}</span></h1>
      <p>Target <b>{_esc(v['target'])}</b> &nbsp;·&nbsp; <span id='jbadge'>{_badge(v['status'])}</span>
         &nbsp;·&nbsp; started {_esc(v['started'])} &nbsp;·&nbsp; <a href='/{{q}}'>dashboard</a></p>
      <a id='resultlink' style='display:none' href='/targets/{_esc(v['target'])}{{q}}'>→ View results</a>
      <h2 style='margin-top:14px'>Live log</h2>
      <pre id='log'>{_esc(v['log']) or '(waiting for output…)'}</pre>
    </div>"""
    return _page(f"Job {v['id']}", body, onload=f"pollJob('{_esc(job_id)}')")


def render_target(target: str) -> str:
    store = _store()
    try:
        findings = store.findings(target, status="open")
        assets = store.assets(target, active_only=True)
        changes = store.changes_since(target, limit=40)
        latest = store.latest_scan(target)
    finally:
        store.close()
    maxr = max([f["business_risk"] or 0 for f in findings], default=1) or 1

    frows = "".join(
        f"<tr><td><b>{(f['business_risk'] or 0):.0f}</b></td>"
        f"<td><div class='bar'><i style='width:{min(100,(f['business_risk'] or 0)/maxr*100):.0f}%'></i></div></td>"
        f"<td>{_sev(f['severity'])}</td><td>{'KEV' if f['kev'] else ''}</td>"
        f"<td>{_esc(f['cve'])}</td><td class='muted'>{_esc(f['attack_techniques'])}</td>"
        f"<td>{_esc(f['name'])}</td><td class='muted'>{_esc(f['matched_at'])}</td></tr>"
        for f in findings) or "<tr><td colspan=8 class='muted'>No open findings.</td></tr>"
    arows = "".join(
        f"<tr><td><span class='pill'>{_esc(a['kind'])}</span></td><td>{_esc(a['key'])}</td>"
        f"<td class='muted'>{_esc((json.loads(a['data']) if a['data'] else {}).get('source',''))}</td></tr>"
        for a in assets[:400]) or "<tr><td colspan=3 class='muted'>No assets.</td></tr>"
    crows = "".join(
        f"<tr><td class='muted'>{_esc(c['created_at'])}</td><td>{_esc(c['change_type'])}</td>"
        f"<td>{_esc(c['subject'])}</td></tr>"
        for c in changes) or "<tr><td colspan=3 class='muted'>No changes.</td></tr>"
    scanned = (f"last scan #{latest['id']} · {latest['finished_at']}"
               if latest else "no completed scans")
    crit = sum(1 for f in findings if (f["severity"] or "").lower() == "critical")
    high = sum(1 for f in findings if (f["severity"] or "").lower() == "high")

    body = f"""
    <p><a href='/{{q}}'>← dashboard</a></p>
    <div class='card'><h1>{_esc(target)}</h1><p class='muted'>{_esc(scanned)}</p>
      <div class='kpis'>
        <div class='kpi'><div class='n' data-v='{len(assets)}'>0</div><div class='l'>assets</div></div>
        <div class='kpi'><div class='n' data-v='{len(findings)}'>0</div><div class='l'>open findings</div></div>
        <div class='kpi'><div class='n' data-v='{crit}'>0</div><div class='l'>critical</div></div>
        <div class='kpi'><div class='n' data-v='{high}'>0</div><div class='l'>high</div></div>
      </div>
      <p style='margin-top:14px'><a href='/targets/{_esc(target)}/report{{q}}'>⬇ Report</a> &nbsp;·&nbsp;
         <a href='/targets/{_esc(target)}/graph{{q}}'>\U0001f578 Graph</a> &nbsp;·&nbsp;
         <a href='/targets/{_esc(target)}/export.json{{q}}'>JSON</a> &nbsp;·&nbsp;
         <a href='/targets/{_esc(target)}/export.csv{{q}}'>CSV</a></p>
    </div>
    <div class='card'><h2>Findings by business risk</h2>
      <table><tr><th>Risk</th><th></th><th>Sev</th><th>KEV</th><th>CVE</th><th>ATT&CK</th><th>Name</th><th>Location</th></tr>{frows}</table></div>
    <div class='card'><h2>Assets</h2>
      <table><tr><th>Kind</th><th>Asset</th><th>Source</th></tr>{arows}</table></div>
    <div class='card'><h2>Recent changes</h2>
      <table><tr><th>When</th><th>Type</th><th>Subject</th></tr>{crows}</table></div>
    """
    return _page(target, body)


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "ReconEngineASM"

    def log_message(self, *a):  # quieter console
        pass

    # -- helpers --
    def _q(self) -> str:
        tok = _STATE.get("token")
        return f"?token={urllib.parse.quote(str(tok))}" if tok else ""

    def _authed(self) -> bool:
        tok = _STATE.get("token")
        if not tok:
            return True
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        supplied = (self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                    or (qs.get("token", [""])[0]))
        return supplied == tok

    def _send(self, code: int, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _html(self, body: str, code=200):
        # inject token into same-origin links
        self._send(code, body.replace("{q}", self._q()))

    def _redirect(self, loc: str):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    # -- routing --
    def do_GET(self):
        if not self._authed():
            return self._send(401, "unauthorized", "text/plain")
        path = urllib.parse.urlparse(self.path).path
        store_routes = {
            "/": lambda: self._html(render_dashboard()),
        }
        if path in store_routes:
            return store_routes[path]()
        m = re.match(r"^/jobs/([0-9a-f]{6,})$", path)
        if m:
            page = render_job(m.group(1))
            return self._html(page) if page else self._send(404, "no such job", "text/plain")
        m = re.match(r"^/api/jobs/([0-9a-f]{6,})$", path)
        if m:
            with _JOBS_LOCK:
                job = _JOBS.get(m.group(1))
            if not job:
                return self._send(404, json.dumps({"error": "unknown"}), "application/json")
            return self._send(200, json.dumps(_job_view(job)), "application/json")
        m = re.match(r"^/targets/([^/]+)/report$", path)
        if m:
            return self._report(urllib.parse.unquote(m.group(1)))
        m = re.match(r"^/targets/([^/]+)/graph$", path)
        if m:
            t = urllib.parse.unquote(m.group(1))
            s = _store()
            try:
                return self._send(200, graph_html(build_graph(s, t), t))
            finally:
                s.close()
        m = re.match(r"^/api/targets/([^/]+)/graph\.json$", path)
        if m:
            t = urllib.parse.unquote(m.group(1))
            s = _store()
            try:
                return self._send(200, json.dumps(build_graph(s, t)), "application/json")
            finally:
                s.close()
        m = re.match(r"^/targets/([^/]+)/export\.(json|csv)$", path)
        if m:
            return self._export(urllib.parse.unquote(m.group(1)), m.group(2))
        m = re.match(r"^/targets/([^/]+)$", path)
        if m:
            return self._html(render_target(urllib.parse.unquote(m.group(1))))
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        if not self._authed():
            return self._send(401, "unauthorized", "text/plain")
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "ignore"))

        def g(k):
            return (form.get(k, [""])[0]).strip()

        kind = {"/scan": "scan", "/appscan": "appscan",
                "/codescan": "codescan"}.get(path)
        if not kind:
            return self._send(404, "not found", "text/plain")
        target = g("target")
        if not target:
            return self._send(400, "target required", "text/plain")
        opts = {"severity": g("severity"), "org": g("org"),
                "github_token": g("github_token"), "apk": g("apk"),
                "crawl": "crawl" in form, "dirs": "dirs" in form,
                "no_vuln": "no_vuln" in form, "offline": "offline" in form}
        job_id = start_job(kind, target, opts)
        self._redirect(f"/jobs/{job_id}{self._q()}")

    def _report(self, target: str):
        s = _store()
        try:
            out = _runs_dir() / f"{target}_report.html"
            build_asm_report(s, target, str(out))
        finally:
            s.close()
        self._send(200, out.read_bytes(), "text/html",
                   {"Content-Disposition": f'attachment; filename="{target}_asm_report.html"'})

    def _export(self, target: str, fmt: str):
        s = _store()
        try:
            rows = s.findings(target, status="open")
        finally:
            s.close()
        cols = ["business_risk", "risk_score", "severity", "kev", "epss", "cve",
                "attack_techniques", "name", "matched_at", "first_seen_at"]
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(cols)
            for r in rows:
                w.writerow([r[c] for c in cols])
            self._send(200, buf.getvalue(), "text/csv")
        else:
            self._send(200, json.dumps([{c: r[c] for c in cols} for r in rows]),
                       "application/json")


def run_server(config: Config, host: str = "127.0.0.1", port: int = 8000,
               token: Optional[str] = None,
               config_path: Optional[str] = None) -> None:
    _STATE["db"] = config.db
    _STATE["token"] = token
    _STATE["config_path"] = config_path
    _STATE["runs_dir"] = Path(config.db).resolve().parent / ".asm_runs"
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[+] ASM web UI (stdlib, no deps) on http://{host}:{port}  (db={config.db})")
    if host not in ("127.0.0.1", "localhost"):
        print("[!] Non-local bind — protect with --token and a firewall.")
    if token:
        print("[+] Token required: append ?token=... to the URL")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        httpd.server_close()
