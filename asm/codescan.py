"""
Public code / GitHub secret-leak scanner (BeVigil-style).

Searches public GitHub code for references to the target, pulls the matching
files, and runs the same secret/asset extraction the app scanner uses. Leaked
credentials and back-end subdomains found in public repos are folded into the
ASM inventory exactly like any other finding.

Needs a GitHub token (``--github-token`` or ``GITHUB_TOKEN`` env) because the
code-search API requires authentication. Searches PUBLIC code only; it clones
nothing and writes nothing to GitHub. Rate-limited and best-effort: it degrades
to an empty result (never raises) when the token is missing or the API is
unreachable.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from .appscan import extract_surface
from .models import Finding, ScanResult, KIND_SUBDOMAIN, KIND_URL

_API = "https://api.github.com"
_UA = "recon-engine-asm"


def _get(url: str, token: str, accept: str = "application/vnd.github+json",
         timeout: int = 20) -> Optional[dict]:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "User-Agent": _UA, "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 403:  # rate limit / abuse detection
            print("[!] GitHub API rate-limited; backing off")
            time.sleep(5)
        else:
            print(f"[!] GitHub API {exc.code}: {url}")
        return None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] GitHub API error: {exc}")
        return None


def scan_github(target: str, token: Optional[str] = None,
                org: Optional[str] = None, max_files: int = 30) -> Dict:
    """Search public GitHub code for the target and extract leaked surface."""
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    out: Dict[str, object] = {"target": target, "secrets": [], "buckets": [],
                              "subdomains": [], "urls": [], "files": []}
    if not token:
        out["error"] = ("no GitHub token (set GITHUB_TOKEN or pass "
                        "--github-token); code search needs auth")
        return out

    root = target.lstrip("*.")
    # Search queries: the domain itself, plus domain near secret-ish keywords.
    queries = [f'"{root}"']
    if org:
        queries = [f'"{root}" org:{org}', f'org:{org} "api_key"']
    seen_secret, seen_sub, seen_url, seen_bucket = set(), set(), set(), set()

    for q in queries:
        url = f"{_API}/search/code?q={urllib.parse.quote(q)}&per_page={min(max_files,100)}"
        data = _get(url, token)
        if not data:
            continue
        for item in data.get("items", [])[:max_files]:
            repo = (item.get("repository") or {}).get("full_name", "")
            path = item.get("path", "")
            loc = f"{repo}/{path}"
            content = _fetch_blob(item, token)
            if not content:
                continue
            out["files"].append(loc)
            surf = extract_surface(content, target)
            for s in surf["secrets"]:
                k = (s["type"], s["value"])
                if k not in seen_secret:
                    seen_secret.add(k)
                    s["location"] = loc
                    out["secrets"].append(s)
            for b in surf["buckets"]:
                if b["ref"] not in seen_bucket:
                    seen_bucket.add(b["ref"])
                    out["buckets"].append(b)
            for sub in surf["subdomains"]:
                if sub not in seen_sub:
                    seen_sub.add(sub)
                    out["subdomains"].append(sub)
            for u in surf["urls"]:
                if u not in seen_url:
                    seen_url.add(u)
                    out["urls"].append(u)
            time.sleep(0.3)   # be gentle with the API
        time.sleep(2)         # code search is 10 req/min

    out["subdomains"] = sorted(seen_sub)
    return out


def _fetch_blob(item: dict, token: str) -> Optional[str]:
    """Fetch a code-search hit's file content (base64 git blob -> text)."""
    api_url = item.get("url")       # contents API url for the file
    if not api_url:
        return None
    data = _get(api_url, token)
    if not data:
        return None
    content = data.get("content")
    if content and data.get("encoding") == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", "ignore")
        except Exception:
            return None
    return None


def to_scan_result(scan: Dict, target: str) -> ScanResult:
    """Fold GitHub code-leak findings into an ASM ScanResult."""
    res = ScanResult(target=target, results_dir="codescan:github")
    for sub in scan.get("subdomains", []):
        res.add_asset(KIND_SUBDOMAIN, sub, source="github")
    for url in scan.get("urls", []):
        import re
        host = re.sub(r"^https?://", "", url).split("/", 1)[0]
        res.add_asset(KIND_URL, host, url=url, source="github")
    for s in scan.get("secrets", []):
        loc = s.get("location", "github")
        res.add_finding(Finding(
            template_id=f"codeleak-{s['type'].lower().replace(' ', '-')}",
            name=f"Leaked secret in public code: {s['type']}",
            severity=s["severity"], matched_at=loc,
            info={"tags": ["secret", "credential", "code-leak"],
                  "value": s["value"], "location": loc}))
    for b in scan.get("buckets", []):
        res.add_finding(Finding(
            template_id="codeleak-cloud-storage",
            name=f"Cloud storage reference in public code ({b['type']})",
            severity="medium", matched_at=b["ref"],
            info={"tags": ["exposure", "cloud", "code-leak"]}))
        res.add_asset(KIND_URL, b["ref"], source="github", cloud=b["type"])
    return res
