"""
Attack-path correlation engine.

Individual findings are rarely the whole story — the value is in the *chain*:
a leaked key plus an exposed bucket is data exfiltration; an exposed .git on a
live host is full source disclosure; a database port open to the world next to
a default-login finding is a breach waiting to happen.

This engine reads the inventory (assets, findings, relationships already stored
for a target) and derives higher-severity **attack-chain findings** when a
dangerous combination of signals co-occurs. It is deterministic and rule-based
— the realistically automatable slice of "complex" findings, not a promise to
replace a human tester.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .models import Finding
from .store import Store, _host_of

# Ports that are high-value when exposed to the internet.
_SENSITIVE_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "3306": "MySQL",
    "5432": "PostgreSQL", "6379": "Redis", "9200": "Elasticsearch",
    "27017": "MongoDB", "5900": "VNC", "11211": "Memcached",
    "2375": "Docker API", "9000": "management", "8080": "app-mgmt",
    "15672": "RabbitMQ mgmt", "5601": "Kibana",
}


def _tags(row) -> set:
    try:
        info = json.loads(row["info"]) if row["info"] else {}
    except (TypeError, json.JSONDecodeError):
        info = {}
    t = info.get("tags")
    return {str(x).lower() for x in t} if isinstance(t, list) else set()


def _chain(name: str, severity: str, host: str, evidence: List[str],
           techniques: List[dict], template: str) -> Finding:
    return Finding(
        template_id=template, name=name, severity=severity,
        matched_at=host or "multiple",
        info={"tags": ["attack-chain"], "chain": evidence},
        attack=techniques,
        attack_techniques=",".join(t["technique_id"] for t in techniques),
    )


_T = {  # reusable ATT&CK technique records
    "cred": {"tactic_id": "TA0006", "tactic": "Credential Access",
             "technique_id": "T1552", "technique": "Unsecured Credentials"},
    "collect": {"tactic_id": "TA0009", "tactic": "Collection",
                "technique_id": "T1213", "technique": "Data from Information Repositories"},
    "exfil": {"tactic_id": "TA0010", "tactic": "Exfiltration",
              "technique_id": "T1537", "technique": "Transfer to Cloud Account"},
    "valid": {"tactic_id": "TA0001", "tactic": "Initial Access",
              "technique_id": "T1078", "technique": "Valid Accounts"},
    "exposed": {"tactic_id": "TA0001", "tactic": "Initial Access",
                "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "takeover": {"tactic_id": "TA0042", "tactic": "Resource Development",
                 "technique_id": "T1584.001", "technique": "Domains"},
    "remote": {"tactic_id": "TA0008", "tactic": "Lateral Movement",
               "technique_id": "T1021", "technique": "Remote Services"},
}


def correlate(store: Store, target: str) -> List[Finding]:
    """Derive attack-chain findings from the target's current inventory."""
    findings = store.findings(target, status="open")
    assets = store.assets(target, active_only=True)
    if not findings:
        return []

    live_hosts = {a["key"] for a in assets if a["kind"] in ("url", "subdomain")}
    services = [a for a in assets if a["kind"] == "service"]

    # Classify findings once.
    secrets, exposures, takeovers, defaults, cloud_refs = [], [], [], [], []
    for f in findings:
        tags = _tags(f)
        tid = (f["template_id"] or "").lower()
        if "secret" in tags or "credential" in tags or "secret" in tid:
            secrets.append(f)
        if ("exposure" in tags or "disclosure" in tags
                or any(k in tid for k in ("git", "env", "exposure", "backup"))):
            exposures.append(f)
        if "takeover" in tags or "takeover" in tid:
            takeovers.append(f)
        if "default-login" in tags or "default" in tid:
            defaults.append(f)
        if "cloud" in tags or any(k in tid for k in ("s3", "bucket", "cloud-storage")):
            cloud_refs.append(f)

    chains: List[Finding] = []

    # 1. Leaked credential + reachable infrastructure -> credential access path
    if secrets and live_hosts:
        names = sorted({s["name"] for s in secrets})[:5]
        chains.append(_chain(
            "Attack chain: leaked credentials usable against live infrastructure",
            "critical", next(iter(secrets))["matched_at"],
            [f"{len(secrets)} leaked secret(s): {', '.join(names)}",
             f"{len(live_hosts)} live host(s)/endpoints discovered",
             "A valid credential + reachable service is a direct initial-access path"],
            [_T["cred"], _T["valid"]], "chain-cred-to-infra"))

    # 2. Cloud key + exposed bucket -> data exfiltration path
    cloud_keys = [s for s in secrets if any(k in (s["name"] or "").lower()
                  for k in ("aws", "gcp", "google", "azure", "firebase"))]
    if cloud_keys and cloud_refs:
        chains.append(_chain(
            "Attack chain: cloud credential + exposed storage = data exfiltration",
            "critical", cloud_keys[0]["matched_at"],
            [f"Cloud credential leaked: {cloud_keys[0]['name']}",
             f"Exposed cloud storage: {cloud_refs[0]['matched_at']}",
             "The key likely authorises access to the exposed storage"],
            [_T["cred"], _T["exfil"], _T["collect"]], "chain-cloud-key-bucket"))

    # 3. Source/secret exposure on a live host -> source disclosure
    for e in exposures:
        host = _host_of(e["matched_at"])
        if host and host in live_hosts:
            chains.append(_chain(
                "Attack chain: source/config exposure on a live host",
                "high", e["matched_at"],
                [f"Exposure: {e['name']} at {e['matched_at']}",
                 f"Host {host} is live and reachable",
                 "Exposed source/config often leaks further secrets & internal paths"],
                [_T["exposed"], _T["collect"]], f"chain-exposure-{host}"))

    # 4. Subdomain takeover -> hostile control of your namespace
    for tk in takeovers:
        chains.append(_chain(
            "Attack chain: subdomain takeover enables phishing / cookie theft",
            "high", tk["matched_at"],
            [f"Takeover: {tk['name']} at {tk['matched_at']}",
             "An attacker controls content on your trusted domain",
             "Usable for phishing, OAuth/cookie theft and brand abuse"],
            [_T["takeover"]], f"chain-takeover-{_host_of(tk['matched_at'])}"))

    # 5. Sensitive service exposed to the internet (optionally + default login)
    default_hosts = {_host_of(d["matched_at"]) for d in defaults}
    for svc in services:
        try:
            data = json.loads(svc["data"]) if svc["data"] else {}
        except (TypeError, json.JSONDecodeError):
            data = {}
        ip, port = (svc["key"].split(":", 1) + [""])[:2]
        label = _SENSITIVE_PORTS.get(port)
        if not label:
            continue
        sev = "critical" if (ip in default_hosts or port in
                             ("3306", "5432", "6379", "9200", "27017", "2375")) else "high"
        ev = [f"{label} service exposed at {svc['key']}",
              data.get("product") and f"Service banner: {data.get('product')} {data.get('version','')}".strip() or
              "Reachable from the public internet"]
        if ip in default_hosts:
            ev.append("A default/weak-login finding exists on this host")
        chains.append(_chain(
            f"Attack chain: internet-exposed {label} service",
            sev, svc["key"], ev, [_T["remote"], _T["exposed"]],
            f"chain-service-{svc['key']}"))

    return chains


def run_correlation(store: Store, target: str) -> int:
    """Correlate and persist chain findings onto the target's latest scan."""
    chains = correlate(store, target)
    if chains:
        store.add_derived_findings(target, chains)
    return len(chains)
