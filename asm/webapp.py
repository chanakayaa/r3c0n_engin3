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
:root{
 --ink:#070a12;--ink2:#0a0f1b;--surface:rgba(255,255,255,.028);
 --surface2:rgba(255,255,255,.045);--line:rgba(148,178,220,.12);
 --fg:#e9f0fa;--muted:#8ba0c2;--faint:#5c6e8c;
 --brand:#2dd4bf;--brand2:#14b8a6;--signal:#fbbf24;--danger:#fb7185;
 --radius:18px;--shadow:0 24px 60px -24px rgba(0,0,0,.65);
 --disp:'Sora',-apple-system,'Segoe UI',sans-serif;
 --body:'IBM Plex Sans',-apple-system,'Segoe UI',sans-serif;
 --mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:var(--body);color:var(--fg);min-height:100vh;
background:
 radial-gradient(900px 520px at 88% -8%,rgba(45,212,191,.10),transparent 60%),
 radial-gradient(820px 520px at -6% 8%,rgba(251,191,36,.07),transparent 55%),
 linear-gradient(180deg,var(--ink2),var(--ink));
background-attachment:fixed;-webkit-font-smoothing:antialiased;letter-spacing:.1px}
/* subtle film grain for depth */
body::after{content:"";position:fixed;inset:0;pointer-events:none;opacity:.5;z-index:0;
background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.028'/%3E%3C/svg%3E")}
a{color:var(--brand);text-decoration:none}a:hover{color:#5eead4}
/* ---- product shell ---- */
.shell{display:grid;grid-template-columns:248px 1fr;min-height:100vh;position:relative;z-index:1}
.side{border-right:1px solid var(--line);padding:22px 18px;display:flex;flex-direction:column;
gap:6px;position:sticky;top:0;height:100vh;background:linear-gradient(180deg,rgba(255,255,255,.02),transparent)}
.brand{display:flex;align-items:center;gap:11px;margin-bottom:22px;animation:fadeDown .5s ease both}
.brand .mark{width:34px;height:34px;flex:none}
.brand .nm{font-family:var(--disp);font-weight:700;font-size:16px;line-height:1.05}
.brand .nm span{display:block;font-family:var(--body);font-weight:500;font-size:10.5px;
color:var(--faint);letter-spacing:1.4px;text-transform:uppercase;margin-top:3px}
.nav{display:flex;flex-direction:column;gap:3px;margin-top:4px}
.nav a{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:11px;
color:var(--muted);font-weight:500;font-size:14px;transition:.18s}
.nav a:hover{background:var(--surface);color:var(--fg)}
.nav a.on{background:linear-gradient(90deg,rgba(45,212,191,.16),rgba(45,212,191,.03));
color:#7df0e0;box-shadow:inset 2px 0 0 var(--brand)}
.nav a .i{width:17px;text-align:center;opacity:.9}
.side .foot{margin-top:auto;font-size:11px;color:var(--faint);line-height:1.6;
border-top:1px solid var(--line);padding-top:14px}
.side .foot b{color:var(--muted);font-weight:600}
.main{padding:30px 40px 60px;max-width:1120px;animation:fadeIn .5s ease both}
.ptitle{font-family:var(--disp);font-weight:700;font-size:26px;margin:0 0 2px;
letter-spacing:-.4px}
.pdesc{color:var(--muted);font-size:13.5px;margin:0 0 20px}
/* staggered reveal for main children */
.main>.card{opacity:0;animation:rise .6s cubic-bezier(.22,1,.36,1) forwards}
.main>.card:nth-child(1){animation-delay:.04s}.main>.card:nth-child(2){animation-delay:.12s}
.main>.card:nth-child(3){animation-delay:.2s}.main>.card:nth-child(4){animation-delay:.28s}
.main>.card:nth-child(5){animation-delay:.36s}
.card{background:var(--surface);backdrop-filter:blur(8px);border:1px solid var(--line);
border-radius:var(--radius);padding:22px;margin:0 0 20px;box-shadow:var(--shadow)}
.card.hero{background:
 radial-gradient(500px 240px at 100% 0,rgba(45,212,191,.10),transparent 60%),var(--surface)}
h2{font-family:var(--disp);font-weight:600;color:var(--fg);margin:0 0 14px;font-size:16px;
letter-spacing:-.2px}
h2 .hint{font-family:var(--body);font-weight:400;color:var(--faint);font-size:12px;margin-left:8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px}
.kpi{background:var(--surface2);border:1px solid var(--line);border-radius:14px;padding:16px 18px;
transition:transform .22s,box-shadow .22s,border-color .22s;position:relative;overflow:hidden}
.kpi:hover{transform:translateY(-4px);border-color:rgba(45,212,191,.4);
box-shadow:0 16px 34px -18px rgba(45,212,191,.5)}
.kpi .n{font-family:var(--disp);font-size:32px;font-weight:700;line-height:1;letter-spacing:-1px}
.kpi .l{color:var(--muted);font-size:12px;margin-top:7px}
.kpi.crit .n{color:var(--danger)}.kpi.high .n{color:var(--signal)}.kpi.brand .n{color:var(--brand)}
.tabs{display:flex;gap:4px;margin-bottom:18px;background:var(--ink2);border:1px solid var(--line);
border-radius:13px;padding:5px;width:fit-content;max-width:100%;flex-wrap:wrap}
.tab{padding:9px 18px;border-radius:9px;cursor:pointer;color:var(--muted);font-weight:600;
font-size:13.5px;transition:.2s;white-space:nowrap}
.tab:hover{color:var(--fg)}
.tab.active{color:var(--ink);background:linear-gradient(135deg,var(--brand),var(--brand2));
box-shadow:0 6px 18px -8px rgba(45,212,191,.7)}
.pane{display:none}.pane.active{display:block;animation:rise .4s cubic-bezier(.22,1,.36,1) both}
label{display:block;color:var(--muted);font-size:12px;margin:12px 0 5px;font-weight:500}
input[type=text],input[type=password]{width:100%;background:var(--ink);border:1px solid var(--line);
color:var(--fg);padding:12px 13px;border-radius:11px;font-family:var(--body);font-size:14px;
transition:border-color .2s,box-shadow .2s}
input::placeholder{color:var(--faint)}
input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px rgba(45,212,191,.16)}
.row{display:flex;gap:16px;flex-wrap:wrap}.row>div{flex:1;min-width:220px}
.checks{display:flex;gap:18px;flex-wrap:wrap;margin:14px 0;color:var(--muted);font-size:13px}
.checks label{display:inline-flex;align-items:center;gap:8px;margin:0;cursor:pointer}
.checks input{accent-color:var(--brand)}
button{margin-top:16px;background:linear-gradient(135deg,var(--brand),var(--brand2));
color:var(--ink);border:0;padding:13px 22px;border-radius:12px;font-weight:700;font-size:14px;
font-family:var(--disp);cursor:pointer;transition:transform .14s,box-shadow .22s;
box-shadow:0 10px 26px -12px rgba(45,212,191,.75)}
button:hover{transform:translateY(-2px);box-shadow:0 16px 34px -12px rgba(45,212,191,.9)}
button:active{transform:translateY(0)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);font-size:13.5px}
th{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.6px;font-weight:600}
tbody tr{transition:background .15s}tbody tr:hover{background:var(--surface)}
td.num,.mono{font-family:var(--mono);font-size:12.5px}
.sev{font-family:var(--disp);font-weight:700;padding:3px 10px;border-radius:7px;font-size:10.5px;
text-transform:uppercase;letter-spacing:.4px}
.critical{background:rgba(251,113,133,.16);color:#fda4af;border:1px solid rgba(251,113,133,.3)}
.high{background:rgba(251,146,60,.15);color:#fdba74;border:1px solid rgba(251,146,60,.3)}
.medium{background:rgba(251,191,36,.14);color:#fcd34d;border:1px solid rgba(251,191,36,.28)}
.low{background:rgba(96,165,250,.14);color:#93c5fd;border:1px solid rgba(96,165,250,.28)}
.info,.unknown{background:rgba(148,163,184,.14);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)}
.bar{height:6px;border-radius:6px;background:var(--ink);overflow:hidden;min-width:72px}
.bar>i{display:block;height:100%;border-radius:6px;width:0;
background:linear-gradient(90deg,var(--brand),var(--signal),var(--danger));
animation:grow .9s cubic-bezier(.22,1,.36,1) forwards}
.pill{display:inline-block;background:var(--surface2);border:1px solid var(--line);
border-radius:999px;padding:3px 11px;font-size:11px;color:var(--muted);font-family:var(--mono)}
.badge{display:inline-flex;align-items:center;gap:7px;padding:5px 13px;border-radius:999px;
font-weight:700;font-size:12px;font-family:var(--disp)}
.badge.run{background:rgba(45,212,191,.14);color:#5eead4}
.badge.run .dot{width:7px;height:7px;border-radius:50%;background:var(--brand);
box-shadow:0 0 0 0 rgba(45,212,191,.6);animation:pulse 1.4s infinite}
.badge.ok{background:rgba(52,211,153,.14);color:#6ee7b7}
.badge.fail{background:rgba(251,113,133,.14);color:#fda4af}
.spinner{width:16px;height:16px;border:2px solid rgba(45,212,191,.22);border-top-color:var(--brand);
border-radius:50%;display:inline-block;animation:spin .8s linear infinite;vertical-align:-3px}
pre{background:var(--ink);color:#8ef0cf;padding:16px;border-radius:13px;overflow:auto;max-height:500px;
font-family:var(--mono);font-size:12.5px;line-height:1.6;border:1px solid var(--line)}
.muted{color:var(--muted);font-size:13px}
.banner{margin:0 0 20px;padding:11px 16px;border-radius:12px;font-size:12.5px;
background:rgba(251,191,36,.08);color:#fcd34d;border:1px solid rgba(251,191,36,.22);
display:flex;align-items:center;gap:9px;animation:rise .5s ease both}
.toast{position:fixed;right:22px;bottom:22px;background:rgba(45,212,191,.14);color:#5eead4;
padding:13px 20px;border-radius:13px;border:1px solid rgba(45,212,191,.35);font-weight:600;
backdrop-filter:blur(10px);animation:rise .4s ease both;z-index:50}
@keyframes rise{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes fadeDown{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:none}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(45,212,191,.55)}70%{box-shadow:0 0 0 7px rgba(45,212,191,0)}100%{box-shadow:0 0 0 0 rgba(45,212,191,0)}}
@keyframes grow{from{width:0}}
@media(max-width:820px){.shell{grid-template-columns:1fr}.side{position:static;height:auto;
flex-direction:row;flex-wrap:wrap;align-items:center}.side .foot{display:none}
.nav{flex-direction:row;flex-wrap:wrap}.main{padding:22px 18px}}
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
function pollScans(){const tb=document.getElementById('scanrows');if(!tb)return;
async function tick(){try{const r=await fetch('/api/v1/jobs'+location.search);const js=await r.json();
 if(!js.length){tb.innerHTML="<tr><td colspan=5 class=muted>No scans this session.</td></tr>";}
 else{tb.innerHTML=js.map(j=>{const b=j.status==='running'?"<span class='badge run'><span class=dot></span>running</span>":
  (j.status==='completed'?"<span class='badge ok'>completed</span>":"<span class='badge fail'>failed</span>");
  const bar=j.status==='running'?"<div class='bar'><i style='width:100%;animation:none'></i></div>":"";
  return `<tr><td><a href='/jobs/${j.id}${location.search}'>${j.id}</a></td>`+
   `<td><span class=pill>${j.kind}</span></td><td>${j.target}</td><td>${b}${bar}</td>`+
   `<td class=muted>${j.started}</td></tr>`;}).join('');}
 }catch(e){}setTimeout(tick,2000);}tick();}
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _sev(s) -> str:
    s = (s or "unknown").lower()
    return f"<span class='sev {s}'>{_esc(s)}</span>"


_LOGO = ("<svg class='mark' viewBox='0 0 40 40' fill='none' xmlns='http://www.w3.org/2000/svg'>"
         "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>"
         "<stop offset='0' stop-color='#2dd4bf'/><stop offset='1' stop-color='#14b8a6'/>"
         "</linearGradient></defs>"
         "<path d='M20 2 L35 9 V21 C35 30 28 36 20 38 C12 36 5 30 5 21 V9 Z' "
         "fill='url(#g)' opacity='.14' stroke='url(#g)' stroke-width='1.5'/>"
         "<circle cx='20' cy='20' r='10' stroke='url(#g)' stroke-width='1.4' opacity='.5'/>"
         "<circle cx='20' cy='20' r='5' stroke='url(#g)' stroke-width='1.6'/>"
         "<circle cx='20' cy='20' r='2' fill='#2dd4bf'/>"
         "<path d='M20 20 L31 11' stroke='#2dd4bf' stroke-width='1.6' stroke-linecap='round'/>"
         "</svg>")

_FONTS = ("<link rel='preconnect' href='https://fonts.googleapis.com'>"
          "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
          "<link href='https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&"
          "family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&"
          "display=swap' rel='stylesheet'>")


def _nav(active: str) -> str:
    items = [("dash", "/", "◉", "Dashboard"),
             ("scan", "/#launch", "⌖", "New scan"),
             ("scans", "/scans", "◷", "Live scans"),
             ("targets", "/#targets", "▤", "Targets")]
    links = "".join(
        f"<a href='{href}{{q}}' class='{'on' if active == key else ''}'>"
        f"<span class='i'>{ic}</span>{label}</a>"
        for key, href, ic, label in items)
    return (f"<aside class='side'><div class='brand'>{_LOGO}"
            f"<div class='nm'>ReconEngine<span>ASM · surface monitor</span></div></div>"
            f"<nav class='nav'>{links}</nav>"
            f"<div class='foot'><b>Localhost only.</b> This console initiates active "
            f"scans — authorized targets only.</div></aside>")


def _page(title: str, body: str, onload: str = "", active: str = "dash") -> str:
    return (f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)} · ReconEngine ASM</title>{_FONTS}"
            f"<style>{CSS}</style></head><body><div class='shell'>{_nav(active)}"
            f"<main class='main'>{body}</main></div>"
            f"<script>{JS}</script><script>{onload}</script></body></html>")


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
    <h1 class='ptitle'>Attack Surface Console</h1>
    <p class='pdesc'>Discover, monitor and prioritise your external attack surface — web, apps and public code.</p>
    <div class='banner'>⚡ This console initiates active scans. Keep it on localhost; authorized targets only.</div>
    <div class='card hero' id='launch'>
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
    <div class='card'><h2>Scan activity <span class='hint'>this session</span></h2>
      <table><tr><th>Job</th><th>Type</th><th>Target</th><th>Status</th><th>Started</th></tr>{jrows}</table></div>
    <div class='card' id='targets'><h2>Tracked targets</h2>
      <table><tr><th>Target</th><th>Scans</th><th>Assets</th></tr>{trows}</table></div>
    """
    return _page("Console", body, active="dash")


def render_scans() -> str:
    body = """
    <h1 class='ptitle'>Live scan tracker</h1>
    <p class='pdesc'>Real-time status of recon, app and code-leak jobs this session.</p>
    <div class='card'><h2>Scans <span class='hint'>auto-refreshing</span></h2>
      <table><tr><th>Job</th><th>Type</th><th>Target</th><th>Status</th><th>Started</th></tr>
      <tbody id='scanrows'><tr><td colspan=5 class='muted'>Loading…</td></tr></tbody></table></div>
    """
    return _page("Live scans", body, onload="pollScans()", active="scans")


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
    return _page(f"Job {v['id']}", body, onload=f"pollJob('{_esc(job_id)}')",
                 active="scan")


def render_target(target: str) -> str:
    from .compliance import evaluate_all
    from .techstack import tech_inventory
    store = _store()
    try:
        findings = store.findings(target, status="open")
        assets = store.assets(target, active_only=True)
        changes = store.changes_since(target, limit=40)
        latest = store.latest_scan(target)
        compliance = evaluate_all(store, target)
        tech = tech_inventory(store, target)
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

    # Compliance posture cards (ISO 27001 + DPDP)
    _ic = {"pass": "✅", "partial": "➖", "fail": "❌", "manual": "✋"}
    comp_cards = ""
    for fw in compliance.values():
        sc = fw["score"]
        col = "#34d399" if sc >= 75 else ("#fbbf24" if sc >= 50 else "#fb7185")
        rows = "".join(
            f"<tr><td>{_ic[c['status']]}</td><td class='mono'>{_esc(c['id'])}</td>"
            f"<td>{_esc(c['title'])}<div class='muted' style='font-size:12px'>"
            f"{_esc(c['evidence'])}</div><div class='muted' style='font-size:11.5px'>"
            f"↳ how: {_esc(c['how'])}</div></td></tr>"
            for c in fw["controls"])
        cc = fw["counts"]
        comp_cards += (
            f"<div class='card'><h2>{_esc(fw['name'])}</h2>"
            f"<div style='display:flex;align-items:center;gap:18px;margin-bottom:12px'>"
            f"<div style='font-family:var(--disp);font-size:40px;font-weight:700;color:{col}'>{sc}%</div>"
            f"<div class='muted'>assessed {fw['assessed']} · "
            f"✅ {cc['pass']} · ➖ {cc['partial']} · ❌ {cc['fail']} "
            f"· ✋ {cc['manual']} manual</div></div>"
            f"<details><summary class='muted' style='cursor:pointer'>Control detail</summary>"
            f"<table>{rows}</table></details></div>")

    trows = "".join(
        f"<tr><td class='num'>{t['count']}</td><td>{_esc(t['technology'])}</td>"
        f"<td class='muted'>{_esc(', '.join(t['hosts'][:4]))}</td></tr>"
        for t in tech[:40]) or "<tr><td colspan=3 class='muted'>No technologies fingerprinted yet.</td></tr>"

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
    <div class='card'><h2>Technology stack <span class='hint'>CVE watch via <code>asm techstack --cve</code></span></h2>
      <table><tr><th>Hosts</th><th>Technology</th><th>Seen on</th></tr>{trows}</table></div>
    <h2 class='ptitle' style='font-size:20px;margin:24px 0 2px'>Compliance posture</h2>
    <p class='pdesc'>Auto-assessed from external signals. Manual controls need internal attestation — this is a posture indicator, not a certification.</p>
    {comp_cards}
    <div class='card'><h2>Recent changes</h2>
      <table><tr><th>When</th><th>Type</th><th>Subject</th></tr>{crows}</table></div>
    """
    return _page(target, body, active="targets")


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
        if path == "/":
            return self._html(render_dashboard())
        if path == "/scans":
            return self._html(render_scans())
        if path == "/api/v1/jobs":
            with _JOBS_LOCK:
                jobs = [_job_view(j) for j in _JOBS.values()]
            jobs.sort(key=lambda j: j["started"], reverse=True)
            return self._send(200, json.dumps(jobs), "application/json")
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
        # ---- REST API (JSON) ----
        if path == "/api/v1/targets":
            s = _store()
            try:
                return self._send(200, json.dumps([dict(r) for r in s.list_targets()]),
                                  "application/json")
            finally:
                s.close()
        m = re.match(r"^/api/v1/targets/([^/]+)/(findings|assets|graph|changes)$", path)
        if m:
            t = urllib.parse.unquote(m.group(1))
            what = m.group(2)
            s = _store()
            try:
                if what == "findings":
                    data = [dict(r) for r in s.findings(t)]
                elif what == "assets":
                    data = [dict(r) for r in s.assets(t)]
                elif what == "changes":
                    data = [dict(r) for r in s.changes_since(t, limit=200)]
                else:
                    data = build_graph(s, t)
            finally:
                s.close()
            return self._send(200, json.dumps(data), "application/json")
        m = re.match(r"^/api/v1/targets/([^/]+)/compliance$", path)
        if m:
            from .compliance import evaluate_all
            t = urllib.parse.unquote(m.group(1))
            s = _store()
            try:
                return self._send(200, json.dumps(evaluate_all(s, t)), "application/json")
            finally:
                s.close()
        m = re.match(r"^/api/v1/targets/([^/]+)/techstack$", path)
        if m:
            from .techstack import tech_inventory
            t = urllib.parse.unquote(m.group(1))
            s = _store()
            try:
                return self._send(200, json.dumps(tech_inventory(s, t)), "application/json")
            finally:
                s.close()
        m = re.match(r"^/api/v1/jobs/([0-9a-f]{6,})$", path)
        if m:
            with _JOBS_LOCK:
                job = _JOBS.get(m.group(1))
            if not job:
                return self._send(404, json.dumps({"error": "unknown"}), "application/json")
            return self._send(200, json.dumps(_job_view(job)), "application/json")

        m = re.match(r"^/targets/([^/]+)$", path)
        if m:
            return self._html(render_target(urllib.parse.unquote(m.group(1))))
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        if not self._authed():
            return self._send(401, "unauthorized", "text/plain")
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length)

        # ---- REST API: trigger a scan with a JSON body ----
        if path == "/api/v1/scans":
            try:
                obj = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._send(400, json.dumps({"error": "invalid json"}), "application/json")
            kind = obj.get("kind", "scan")
            target = (obj.get("target") or "").strip()
            if kind not in ("scan", "appscan", "codescan") or not target:
                return self._send(400, json.dumps(
                    {"error": "need kind in [scan,appscan,codescan] and target"}),
                    "application/json")
            job_id = start_job(kind, target, obj)
            return self._send(202, json.dumps(
                {"job_id": job_id, "status_url": f"/api/v1/jobs/{job_id}"}),
                "application/json")

        form = urllib.parse.parse_qs(raw.decode("utf-8", "ignore"))

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
