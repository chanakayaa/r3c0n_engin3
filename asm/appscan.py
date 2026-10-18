"""
Mobile-app attack-surface scanner (BeVigil-style, static & offline).

Given an APK or IPA, this extracts the attack surface hidden inside the app and
folds it into the ASM inventory:

  * hardcoded secrets (API keys, tokens, private keys)  -> findings
  * cloud storage references (S3 / GCS / Azure / Firebase) -> findings + assets
  * embedded URLs / API endpoints                       -> url assets
  * subdomains of the target discovered in the app      -> subdomain assets
  * third-party trackers / SDKs                          -> info findings
  * requested Android permissions                        -> metadata

No decompiler is required: the app archive is read directly and printable
strings are harvested from its binaries/resources. This is read-only static
analysis of a file you provide — not dynamic testing of a live app.
"""

from __future__ import annotations

import plistlib
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from .models import Finding, ScanResult, KIND_SUBDOMAIN, KIND_URL

# --- secret patterns: name -> (regex, severity) --------------------------- #
_SECRET_PATTERNS = {
    "AWS Access Key ID": (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    "AWS Secret Access Key": (
        re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"), "critical"),
    "Google API Key": (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    "Google OAuth Client": (
        re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"),
        "medium"),
    "Firebase Cloud Messaging Key": (
        re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), "critical"),
    "Slack Token": (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "high"),
    "Stripe Live Secret Key": (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    "Stripe Live Publishable Key": (re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "low"),
    "GitHub Token": (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    "Twilio API Key": (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    "Mailgun API Key": (re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high"),
    "JSON Web Token": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "medium"),
    "Private Key": (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical"),
    "Generic Secret Assignment": (
        re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)"
                   r"['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_./+]{12,}['\"]"), "medium"),
}

# --- cloud storage references --------------------------------------------- #
_BUCKET_PATTERNS = {
    "AWS S3 bucket": re.compile(
        r"\b[a-z0-9.\-]{3,}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b"),
    "AWS S3 (path style)": re.compile(r"\bs3\.amazonaws\.com/[a-z0-9._\-]{3,}\b"),
    "Firebase Realtime DB": re.compile(r"\b[a-z0-9\-]+\.firebaseio\.com\b"),
    "Google App Engine": re.compile(r"\b[a-z0-9\-]+\.appspot\.com\b"),
    "Google Cloud Storage": re.compile(r"\bstorage\.googleapis\.com/[a-z0-9._\-]{3,}\b"),
    "Azure Blob Storage": re.compile(r"\b[a-z0-9]+\.blob\.core\.windows\.net\b"),
}

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\)]{4,}")
_HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
                      re.IGNORECASE)
_PERM_RE = re.compile(r"\bandroid\.permission\.[A-Z_]+\b")

_TRACKERS = {
    "com.google.firebase": "Firebase", "com.google.android.gms.ads": "AdMob",
    "com.facebook": "Facebook SDK", "com.flurry": "Flurry",
    "com.crashlytics": "Crashlytics", "io.branch": "Branch",
    "com.adjust": "Adjust", "com.amplitude": "Amplitude",
    "com.mixpanel": "Mixpanel", "com.appsflyer": "AppsFlyer",
    "com.onesignal": "OneSignal", "com.segment": "Segment",
}

_MAX_PER_KIND = 500


def _printable_strings(data: bytes, min_len: int = 5):
    """Yield printable ASCII and UTF-16LE strings from a binary blob."""
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        yield m.group().decode("ascii", "ignore")
    # UTF-16LE (common in Windows/Android resource strings)
    try:
        text = data.decode("utf-16-le", "ignore")
    except Exception:
        return
    for s in re.findall(r"[\x20-\x7e]{%d,}" % min_len, text):
        yield s


def _harvest(archive: zipfile.ZipFile) -> str:
    """Concatenate strings from the interesting entries of an app archive."""
    chunks: List[str] = []
    for info in archive.infolist():
        name = info.filename.lower()
        if info.file_size > 40 * 1024 * 1024:   # skip huge media
            continue
        if not (name.endswith((".dex", ".arsc", ".xml", ".json", ".plist",
                               ".properties", ".js", ".txt", ".so"))
                or "assets/" in name or "/raw/" in name
                or name.endswith(".app/") or "payload/" in name):
            # still scan the main binary of an IPA (no extension)
            if "." in name.rsplit("/", 1)[-1]:
                continue
        try:
            chunks.append("\n".join(_printable_strings(archive.read(info))))
        except (RuntimeError, zipfile.BadZipFile, OSError):
            continue
    return "\n".join(chunks)


def scan_app(path: str, target: Optional[str] = None) -> Dict:
    """Static-analyse an APK/IPA and return the extracted attack surface."""
    p = Path(path)
    out: Dict[str, object] = {
        "app": p.name, "secrets": [], "buckets": [], "urls": [],
        "subdomains": [], "domains": [], "trackers": [], "permissions": [],
    }
    if not p.exists():
        out["error"] = f"file not found: {path}"
        return out
    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile:
        out["error"] = "not a valid APK/IPA (zip) archive"
        return out

    with zf:
        blob = _harvest(zf)

    # secrets (dedupe by type+value)
    seen_secret = set()
    for name, (rx, sev) in _SECRET_PATTERNS.items():
        for m in rx.finditer(blob):
            val = m.group(0)
            key = (name, val)
            if key in seen_secret:
                continue
            seen_secret.add(key)
            out["secrets"].append({"type": name, "severity": sev,
                                   "value": val[:80]})

    # cloud buckets
    seen_bucket = set()
    for name, rx in _BUCKET_PATTERNS.items():
        for m in rx.finditer(blob):
            v = m.group(0)
            if v not in seen_bucket:
                seen_bucket.add(v)
                out["buckets"].append({"type": name, "ref": v})

    # urls + hosts
    urls = sorted({m.group(0).rstrip('.,)";\'') for m in _URL_RE.finditer(blob)})
    out["urls"] = urls[:_MAX_PER_KIND]
    hosts = {h.lower() for h in _HOST_RE.findall(blob)}
    # keep plausible hostnames only
    hosts = {h for h in hosts if "." in h and not h.endswith(
        (".png", ".jpg", ".gif", ".so", ".xml", ".json", ".js", ".html"))}
    out["domains"] = sorted(hosts)[:_MAX_PER_KIND]
    if target:
        t = target.lower().lstrip("*.")
        out["subdomains"] = sorted(h for h in hosts
                                   if h == t or h.endswith("." + t))

    # trackers + permissions
    out["trackers"] = sorted({label for pkg, label in _TRACKERS.items()
                              if pkg in blob})
    out["permissions"] = sorted(set(_PERM_RE.findall(blob)))[:_MAX_PER_KIND]
    return out


def to_scan_result(scan: Dict, target: str) -> ScanResult:
    """Turn a scan_app() result into an ASM ScanResult (assets + findings)."""
    app = scan.get("app", "app")
    res = ScanResult(target=target, results_dir=f"appscan:{app}")

    for sub in scan.get("subdomains", []):
        res.add_asset(KIND_SUBDOMAIN, sub, source="mobile-app", app=app)
    for url in scan.get("urls", []):
        host = re.sub(r"^https?://", "", url).split("/", 1)[0]
        res.add_asset(KIND_URL, host, url=url, source="mobile-app", app=app)

    for s in scan.get("secrets", []):
        res.add_finding(Finding(
            template_id=f"appsec-secret-{s['type'].lower().replace(' ', '-')}",
            name=f"Hardcoded secret in app: {s['type']}",
            severity=s["severity"], matched_at=app,
            info={"tags": ["secret", "credential", "mobile"],
                  "value": s["value"], "app": app}))
    for b in scan.get("buckets", []):
        res.add_finding(Finding(
            template_id="appsec-cloud-storage-ref",
            name=f"Cloud storage reference ({b['type']})",
            severity="medium", matched_at=b["ref"],
            info={"tags": ["exposure", "cloud", "mobile"], "app": app}))
        res.add_asset(KIND_URL, b["ref"], source="mobile-app", app=app,
                      cloud=b["type"])
    for t in scan.get("trackers", []):
        res.add_finding(Finding(
            template_id="appsec-tracker",
            name=f"Third-party tracker/SDK: {t}", severity="info",
            matched_at=app, info={"tags": ["privacy", "mobile"], "app": app}))
    return res
