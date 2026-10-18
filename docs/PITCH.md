# ReconEngine ASM — Positioning & Funding Brief

> Working strategy document. Fill the bracketed `[…]` items with your own
> numbers before sharing. Written to be honest with a technical reviewer —
> nothing here overclaims, because security reviewers check.

## One line

**Open-core, app-aware Attack Surface Management for Indian / APAC mid-market —
it finds the external assets, leaked secrets, and exploitable chains that
cheaper scanners miss and enterprise ASM prices out of reach.**

## The problem

Mid-market companies have a sprawling, changing external footprint — domains,
subdomains, cloud assets, **mobile apps, and public code repos** — and no
affordable way to see it the way an attacker does. Enterprise ASM (Recorded
Future, CloudSEK) is priced for large enterprises; cheap scanners produce flat
lists of low-value findings with no prioritisation or correlation.

## Why now

- Attack surface is exploding (cloud, mobile, SaaS, supply chain).
- EPSS + CISA KEV now make **data-driven prioritisation** possible without a
  proprietary intel team.
- Open-source scanners (nuclei, httpx, etc.) are best-in-class and free —
  the differentiator is no longer the scanner, it's **orchestration,
  correlation, and the app/code-leak surface**.

## Product (what exists today)

A working engine, not slideware:

- **Discovery** — subdomains, DNS/IPs, live hosts, ports/services, tech, TLS,
  WAF/CDN (via the standard recon toolchain).
- **Mobile-app attack surface** — static APK/IPA analysis for hardcoded
  secrets, cloud buckets, and back-end subdomains folded into inventory.
- **Public code-leak scan** — GitHub secret/subdomain discovery.
- **Vulnerability + misconfig** — nuclei full templates, dedicated
  takeover / exposure / misconfiguration passes.
- **Threat-intel prioritisation** — CISA KEV + EPSS + business-criticality →
  a single business-risk score.
- **Attack-path correlation** — chains individual signals into exploit paths
  (leaked key + exposed bucket = exfiltration; .git on a live host = source
  disclosure; DB port + default login = breach).
- **Continuous monitoring** — persistent inventory, scan-diffing, change alerts.
- **Delivery** — animated web console, REST API, HTML/graph reports,
  JSON/CSV export, ticket webhook, Docker image.

## Differentiation (the honest version)

We do **not** claim to beat Recorded Future / CloudSEK "at everything" — they
have proprietary threat-intel and dark-web collection we don't. We win a
specific wedge:

1. **App- and code-leak-first.** Most ASM starts at the domain; we also start
   at the *app and the repo*, where the highest-impact secrets (P1 bug-bounty
   class) actually leak. CloudSEK validates this market; RF is weak here.
2. **Correlation, not lists.** We surface exploit *paths*, ranked by business
   risk — the output a defender can act on, not a 10,000-row CSV.
3. **Open-core & affordable.** The engine is open source (community trust,
   inbound adoption, auditability); the paid tier is hosted continuous
   monitoring, collaboration, and integrations. Priced for Indian mid-market.
4. **Data-residency / DSCI alignment.** India-hosted, self-hostable (Docker),
   no mandatory data egress — a real buying criterion locally.

## Competitive landscape (honest)

| | Recorded Future ASM | CloudSEK | **ReconEngine ASM** |
|---|---|---|---|
| Proprietary threat-intel / dark web | ✅ (core moat) | ✅ | ❌ (use free KEV/EPSS) |
| Global internet-scan data | ✅ | partial | ❌ (scan on demand) |
| Mobile-app secret/asset surface | weak | ✅ | ✅ |
| Public code-leak | partial | ✅ | ✅ |
| Attack-path correlation | ✅ | partial | ✅ (automatable subset) |
| Open-source / self-host | ❌ | ❌ | ✅ |
| Price point | enterprise | enterprise | **mid-market** |

## Moat (what compounds over time)

We can't buy a 15-year intel archive. What we *can* compound:
- **Per-customer change history** — the longer we monitor, the more valuable
  the diff/trend data becomes (switching cost).
- **Open-source community** — contributors, templates, trust, inbound funnel.
- **App/code-leak corpus** — fingerprints and detections improve with volume.

## Business model

Open-core: MIT engine (self-host free) → paid cloud (continuous monitoring,
multi-user/RBAC, integrations, support, compliance reports). Land via the OSS
funnel, expand to paid monitoring.

## Roadmap to commercial-grade (honest effort estimate)

- **Now → 3 mo:** Postgres backend, multi-user auth + RBAC, hardened API,
  Docker/compose (API + Docker shipped), scope allow-lists.
- **3–9 mo:** distributed scan workers + queue, cloud asset discovery
  (AWS/Azure/GCP), CT-log/passive-DNS discovery, scheduled monitoring + alerting
  at scale, SIEM/SOAR/Jira integrations.
- **9–18 mo:** SaaS multi-tenancy, compliance (audit logs, data retention,
  SOC2 path), marketplace of detections, managed-service tier.

## Honest risks (a reviewer will ask)

- **No proprietary intel moat** — mitigated by open-core community + accumulated
  monitoring data + the app/code-leak wedge.
- **Automated "complex" vuln discovery is bounded** — we do the automatable
  correlation well; we do not claim to replace human pentesters.
- **Crowded tooling space** — mitigated by focus (app-aware, mid-market, India)
  rather than feature breadth.

## The ask

`[funding amount]` to reach `[milestone: e.g. 10 design partners + paid pilot]`
over `[N] months`, hiring `[roles]`, with `[your traction / pilots so far]`.

---

*Status of claims in this doc: every capability under "Product (what exists
today)" is implemented and tested in this repository. Everything under
"Roadmap" is not yet built and is labelled as such.*
