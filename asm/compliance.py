"""
Compliance posture engine — ISO/IEC 27001:2022 and India's DPDP Act, 2023.

Maps the *externally observable* security signals the tool already collects
(findings, exposed services, TLS state, leaked secrets, monitoring coverage)
onto control points of each framework, and produces, per control:

  * the control point (what the framework requires),
  * how to achieve it,
  * what the tool observed / did (evidence),
  * a status: pass / partial / fail / manual,

and an overall weighted compliance score per framework.

IMPORTANT (honesty): external ASM can only assess the subset of controls that
leave an outside-visible footprint. Governance, policy, HR and physical
controls are marked ``manual`` and excluded from the automated score — the tool
flags them for human attestation rather than pretending to certify them. This
is a posture indicator, not a certification.
"""

from __future__ import annotations

import json
from typing import Dict, List, Tuple

from .store import Store, _host_of

PASS, PARTIAL, FAIL, MANUAL = "pass", "partial", "fail", "manual"
_VALUE = {PASS: 1.0, PARTIAL: 0.5, FAIL: 0.0}

_SENSITIVE_PORTS = {"22", "23", "3389", "3306", "5432", "6379", "9200",
                    "27017", "5900", "11211", "2375"}


# --------------------------------------------------------------------------- #
# Build an evaluation context from the inventory, once per run.
# --------------------------------------------------------------------------- #

def _ctx(store: Store, target: str) -> Dict:
    findings = store.findings(target, status="open")
    assets = store.assets(target, active_only=True)
    scans = store.scan_history(target, limit=50)

    def tags(f):
        try:
            return {str(x).lower() for x in (json.loads(f["info"]) or {}).get("tags", [])}
        except (TypeError, json.JSONDecodeError):
            return set()

    tls = [f for f in findings if "tls" in tags(f)
           or any(k in (f["name"] or "").lower()
                  for k in ("hsts", "strict-transport", "tls", "ssl", "https"))]
    secrets = [f for f in findings if {"secret", "credential"} & tags(f)
               or "secret" in (f["template_id"] or "")]
    misconfig = [f for f in findings if {"misconfig", "cors", "redirect",
                 "exposed-panel"} & tags(f)
                 or "header" in (f["name"] or "").lower()]
    exposures = [f for f in findings if {"exposure", "disclosure"} & tags(f)]
    takeovers = [f for f in findings if "takeover" in tags(f)]
    chains = [f for f in findings if "attack-chain" in tags(f)]
    high = [f for f in findings
            if (f["severity"] or "").lower() in ("critical", "high")]
    exposed_services = [a for a in assets if a["kind"] == "service"
                        and a["key"].rsplit(":", 1)[-1] in _SENSITIVE_PORTS]
    return {
        "findings": findings, "assets": assets, "scans": scans,
        "tls": tls, "secrets": secrets, "misconfig": misconfig,
        "exposures": exposures, "takeovers": takeovers, "chains": chains,
        "high": high, "exposed_services": exposed_services,
    }


# --------------------------------------------------------------------------- #
# Reusable evaluators: ctx -> (status, evidence)
# --------------------------------------------------------------------------- #

def _ev_crypto(c) -> Tuple[str, str]:
    if c["tls"]:
        return FAIL, (f"{len(c['tls'])} transport-security gap(s): "
                      + ", ".join(sorted({f['name'] for f in c['tls']}))[:160])
    return PASS, "No missing-HSTS / no-redirect / weak-TLS findings observed."


def _ev_vuln_mgmt(c) -> Tuple[str, str]:
    if not c["scans"]:
        return FAIL, "No scans on record."
    if c["high"]:
        return FAIL, (f"{len(c['high'])} open high/critical finding(s) — "
                      "unremediated technical vulnerabilities.")
    return (PASS if len(c["scans"]) > 1 else PARTIAL), (
        f"Continuous scanning in place ({len(c['scans'])} scans); "
        "no open high/critical findings.")


def _ev_config(c) -> Tuple[str, str]:
    if c["misconfig"]:
        return (FAIL if len(c["misconfig"]) > 3 else PARTIAL), (
            f"{len(c['misconfig'])} hardening/misconfiguration gap(s) "
            "(headers, CORS, exposed panels).")
    return PASS, "No missing security headers / misconfigurations observed."


def _ev_data_leak(c) -> Tuple[str, str]:
    if c["secrets"]:
        return FAIL, (f"{len(c['secrets'])} leaked secret(s)/credential(s) "
                      "found in apps or public code.")
    return PASS, "No hardcoded/leaked secrets observed in apps or public code."


def _ev_network(c) -> Tuple[str, str]:
    if c["exposed_services"]:
        svcs = ", ".join(a["key"] for a in c["exposed_services"])[:160]
        return FAIL, f"Sensitive services exposed to the internet: {svcs}"
    return PASS, "No sensitive (DB/SSH/RDP/…) services exposed to the internet."


def _ev_threat_intel(c) -> Tuple[str, str]:
    return PASS, ("Findings enriched with CISA KEV + EPSS exploit intelligence "
                  "and risk-prioritised.")


def _ev_monitoring(c) -> Tuple[str, str]:
    n = len(c["scans"])
    if n > 1:
        return PASS, f"Attack surface monitored continuously ({n} scans; change-diffing on)."
    if n == 1:
        return PARTIAL, "One scan on record — enable scheduled monitoring for continuity."
    return FAIL, "No monitoring on record."


def _ev_app_sec(c) -> Tuple[str, str]:
    app = [f for f in c["secrets"] if "app" in (f["template_id"] or "")]
    if app:
        return FAIL, f"{len(app)} secret(s) hardcoded in mobile app(s)."
    return PASS, "No secrets hardcoded in analysed mobile apps."


def _ev_breach_prevention(c) -> Tuple[str, str]:
    bad = c["secrets"] + c["exposed_services"] + c["exposures"] + c["chains"]
    if bad:
        return FAIL, (f"{len(bad)} exposure(s) that could lead to a personal-data "
                      "breach (leaked creds, exposed stores, attack chains).")
    return PASS, "No externally observable personal-data breach exposure."


def _ev_access_control(c) -> Tuple[str, str]:
    defaults = [f for f in c["findings"] if "default" in (f["template_id"] or "")]
    panels = [f for f in c["misconfig"] if "panel" in (f["name"] or "").lower()]
    if defaults or panels or c["exposed_services"]:
        return FAIL, "Default logins / exposed admin panels / exposed services detected."
    return PASS, "No default-credential, exposed-panel or exposed-service signals."


def _ev_manual(c) -> Tuple[str, str]:
    return MANUAL, "Not externally assessable — requires internal policy/evidence review."


_EVAL = {
    "crypto": _ev_crypto, "vuln_mgmt": _ev_vuln_mgmt, "config": _ev_config,
    "data_leak": _ev_data_leak, "network": _ev_network, "intel": _ev_threat_intel,
    "monitoring": _ev_monitoring, "appsec": _ev_app_sec, "access": _ev_access_control,
    "breach": _ev_breach_prevention, "manual": _ev_manual,
}


# --------------------------------------------------------------------------- #
# Frameworks (control point, how-to, evaluator signal)
# --------------------------------------------------------------------------- #

def _c(cid, title, control, how, signal):
    return {"id": cid, "title": title, "control": control, "how": how, "signal": signal}

ISO27001 = [
    _c("A.5.7", "Threat intelligence",
       "Collect and analyse information about threats to produce threat intelligence.",
       "Feed KEV/EPSS and exploit data into prioritisation; subscribe to vuln feeds.", "intel"),
    _c("A.5.23", "Information security for cloud services",
       "Manage security of cloud service usage.",
       "Inventory cloud assets, lock down buckets, rotate cloud keys.", "data_leak"),
    _c("A.8.8", "Management of technical vulnerabilities",
       "Obtain information about technical vulnerabilities and take action.",
       "Run continuous vuln scanning; remediate high/critical promptly.", "vuln_mgmt"),
    _c("A.8.9", "Configuration management",
       "Establish and monitor secure configurations of hardware/software/services.",
       "Fix security headers, CORS, remove exposed panels; baseline configs.", "config"),
    _c("A.8.12", "Data leakage prevention",
       "Prevent unauthorised disclosure/extraction of information.",
       "Remove hardcoded secrets from apps/code; scan repos; rotate exposed keys.", "data_leak"),
    _c("A.8.16", "Monitoring activities",
       "Monitor networks, systems and applications for anomalous behaviour.",
       "Enable continuous attack-surface monitoring with change alerts.", "monitoring"),
    _c("A.8.20", "Networks security",
       "Secure and manage networks to protect information in systems.",
       "Close/segment exposed management & database services.", "network"),
    _c("A.8.23", "Web filtering / exposure",
       "Manage access to external websites and reduce exposed web surface.",
       "Remove exposed panels, directory listings, dangling subdomains.", "access"),
    _c("A.8.24", "Use of cryptography",
       "Protect information in transit/at rest with cryptography.",
       "Enforce HTTPS + HSTS, redirect HTTP, use strong TLS config.", "crypto"),
    _c("A.8.26", "Application security requirements",
       "Identify and apply security requirements for applications.",
       "Scan mobile apps for secrets; secure APIs; fix app findings.", "appsec"),
    _c("A.5.1", "Policies for information security",
       "Define, approve and communicate information security policies.",
       "Maintain and review an ISMS policy set.", "manual"),
    _c("A.6.3", "Security awareness, education and training",
       "Provide security awareness training to personnel.",
       "Run periodic awareness programmes; track completion.", "manual"),
]

DPDP = [
    _c("DPDP-8(5)", "Reasonable security safeguards",
       "A Data Fiduciary must protect personal data with reasonable security safeguards to prevent a breach.",
       "Encrypt in transit, remove exposed data stores & leaked credentials, patch vulns.", "breach"),
    _c("DPDP-8(5)-crypto", "Protection of data in transit",
       "Personal data must be protected during transmission.",
       "Enforce HTTPS + HSTS everywhere; redirect HTTP; strong TLS.", "crypto"),
    _c("DPDP-ACCESS", "Access control over personal data",
       "Restrict access to systems processing personal data.",
       "Eliminate default logins, exposed admin panels and open data services.", "access"),
    _c("DPDP-LEAK", "Prevention of unauthorised disclosure",
       "Prevent accidental disclosure of personal data (e.g. via apps, code, storage).",
       "Remove hardcoded secrets, secure buckets, scan public code.", "data_leak"),
    _c("DPDP-BREACH", "Personal data breach exposure",
       "Minimise conditions that could lead to a personal data breach.",
       "Close exposed services, fix attack chains, remediate high-risk findings.", "breach"),
    _c("DPDP-8(6)", "Breach detection & notification readiness",
       "Detect breaches and be able to notify the Board and affected principals.",
       "Continuous monitoring + alerting + change tracking for timely detection.", "monitoring"),
    _c("DPDP-8(7)", "Storage limitation / data minimisation",
       "Erase personal data when no longer necessary.",
       "Define retention & deletion; inventory where personal data lives.", "manual"),
    _c("DPDP-5", "Notice & consent",
       "Give notice and obtain consent before processing personal data.",
       "Implement consent notices and records.", "manual"),
]

FRAMEWORKS = {
    "iso27001": {"name": "ISO/IEC 27001:2022 (Annex A, external-observable subset)",
                 "controls": ISO27001},
    "dpdp": {"name": "Digital Personal Data Protection Act, 2023 (India)",
             "controls": DPDP},
}


def evaluate(store: Store, target: str, framework: str) -> Dict:
    fw = FRAMEWORKS[framework]
    ctx = _ctx(store, target)
    rows, num, den = [], 0.0, 0.0
    counts = {PASS: 0, PARTIAL: 0, FAIL: 0, MANUAL: 0}
    for ctrl in fw["controls"]:
        status, evidence = _EVAL[ctrl["signal"]](ctx)
        counts[status] += 1
        if status != MANUAL:
            num += _VALUE[status]
            den += 1
        rows.append({**{k: ctrl[k] for k in ("id", "title", "control", "how")},
                     "status": status, "evidence": evidence})
    score = round(100 * num / den, 1) if den else 0.0
    return {"framework": framework, "name": fw["name"], "score": score,
            "assessed": int(den), "counts": counts, "controls": rows}


def evaluate_all(store: Store, target: str) -> Dict[str, Dict]:
    return {fw: evaluate(store, target, fw) for fw in FRAMEWORKS}
