"""
Turn a ReconEngine results directory into a structured :class:`ScanResult`.

The recon engine writes plain-text / json artifacts under
``results/<target>_<ts>/recon`` and ``.../scans``. This module reads those
artifacts back into typed assets & findings so they can be stored and diffed.
Every parser is defensive: a missing or malformed file is skipped, never fatal.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from .models import (
    Finding,
    ScanResult,
    KIND_IP,
    KIND_SERVICE,
    KIND_SUBDOMAIN,
    KIND_TECHNOLOGY,
    KIND_URL,
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_BRACKET_RE = re.compile(r"\[([^\]]*)\]")


def _lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        return [ln.strip() for ln in path.read_text(errors="ignore").splitlines()
                if ln.strip()]
    except OSError:
        return []


def _strip_scheme(url: str) -> str:
    return re.sub(r"^https?://", "", url).rstrip("/")


def ingest_results(target: str, base_dir: str) -> ScanResult:
    base = Path(base_dir)
    recon = base / "recon"
    scans = base / "scans"
    result = ScanResult(target=target, results_dir=str(base))

    _ingest_subdomains(recon, result)
    _ingest_ips(recon, result)
    _ingest_live_urls(recon, result)
    _ingest_httpx_tech(recon, result)
    _ingest_nmap(scans, result)
    _ingest_nuclei(recon, scans, result)
    _ingest_security_headers(recon, result)

    return result


def _ingest_subdomains(recon: Path, result: ScanResult) -> None:
    for sub in _lines(recon / "subdomains.txt"):
        result.add_asset(KIND_SUBDOMAIN, sub)


def _ingest_ips(recon: Path, result: ScanResult) -> None:
    for ip in _lines(recon / "domain_ips.txt"):
        m = _IP_RE.search(ip)
        if m:
            result.add_asset(KIND_IP, m.group(1))


def _ingest_live_urls(recon: Path, result: ScanResult) -> None:
    for line in _lines(recon / "alive_domains.txt"):
        url = line.split()[0] if line.split() else line
        result.add_asset(KIND_URL, _strip_scheme(url), url=url)


def _ingest_httpx_tech(recon: Path, result: ScanResult) -> None:
    """Parse ``httpx -tech-detect`` lines of the form:

        https://host [200] [Title] [Server] [Tech1,Tech2]
    """
    for line in _lines(recon / "technologies_httpx.txt"):
        parts = line.split(None, 1)
        if not parts:
            continue
        host = _strip_scheme(parts[0])
        for group in _BRACKET_RE.findall(line):
            for token in group.split(","):
                token = token.strip()
                # Heuristic: tech names, not status codes / titles.
                if token and not token.isdigit() and len(token) <= 40:
                    if any(c.isalpha() for c in token):
                        result.add_asset(
                            KIND_TECHNOLOGY, f"{host}|{token}",
                            host=host, technology=token,
                        )


def _ingest_nmap(scans: Path, result: ScanResult) -> None:
    xml_path = scans / "nmap.xml"
    if not xml_path.exists():
        return
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return
    for host in tree.getroot().findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if ip:
            result.add_asset(KIND_IP, ip)
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            service_name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            result.add_asset(
                KIND_SERVICE, f"{ip}:{portid}",
                ip=ip, port=portid, protocol=proto,
                service=service_name, product=product, version=version,
            )


def _ingest_nuclei(recon: Path, scans: Path, result: ScanResult) -> None:
    """Read nuclei JSONL output if present (``-jsonl`` format)."""
    for candidate in (recon / "nuclei.jsonl", scans / "nuclei.jsonl",
                      recon / "nuclei.json", scans / "nuclei.json"):
        if candidate.exists():
            result.findings.extend(parse_nuclei_jsonl(candidate.read_text(errors="ignore")))
            return


def parse_nuclei_jsonl(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        findings.append(Finding(
            template_id=obj.get("template-id", obj.get("templateID", "unknown")),
            name=info.get("name", obj.get("template-id", "unknown")),
            severity=(info.get("severity") or "unknown").lower(),
            matched_at=obj.get("matched-at", obj.get("host", obj.get("matched", ""))),
            info={
                "description": info.get("description", ""),
                "tags": info.get("tags", []),
                "reference": info.get("reference", []),
                "type": obj.get("type", ""),
            },
        ))
    return findings


def _ingest_security_headers(recon: Path, result: ScanResult) -> None:
    """Promote missing critical security headers to low-severity findings."""
    path = recon / "security_headers_raw.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return
    critical = {"strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options"}
    for entry in data if isinstance(data, list) else []:
        url = entry.get("url", "")
        missing = [h for h, v in (entry.get("headers") or {}).items()
                   if v == "missing" and h in critical]
        if missing:
            result.add_finding(Finding(
                template_id="asm-missing-security-headers",
                name="Missing security headers",
                severity="low",
                matched_at=url,
                info={"missing": missing},
            ))
