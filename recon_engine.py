#!/usr/bin/env python3
"""
ReconEngine – Full Pentest Recon & Intelligence Framework
Author: Pushkar Singh
WARNING: Authorized Security Testing Only
"""

import argparse
import subprocess
import shutil
import json
import re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:  # progress bar is optional; degrade to a no-op wrapper
    def tqdm(iterable=None, **kwargs):
        return iterable if iterable is not None else []

MAX_WORKERS = 10

# ================= BANNER =================

def banner():
    print(r"""
__________                                ___________              .__               
\______   \ ____   ____  ____   ____      \_   _____/ ____    ____ |__| ____   ____  
 |       _// __ \_/ ___\/  _ \ /    \      |    __)_ /    \  / ___\|  |/    \_/ __ \ 
 |    |   \  ___/\  \__(  <_> )   |  \     |        \   |  \/ /_/  >  |   |  \  ___/ 
 |____|_  /\___  >\___  >____/|___|  /____/_______  /___|  /\___  /|__|___|  /\___  >
        \/     \/     \/           \/_____/       \/     \//_____/         \/     \/ 

 ReconEngine v9.2 – Pentest Recon & Intelligence Framework
 Author : Pushkar Singh
 WARNING: Authorized Security Testing Only
""")


# ================= CLI =================

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("--crawl", action="store_true")
    p.add_argument("--dirs", action="store_true")
    return p.parse_args()

# ================= ENGINE =================

class ReconEngine:
    def __init__(self, args):
        self.target = args.target
        self.args = args
        self.start = datetime.now()

        ts = self.start.strftime("%Y%m%d_%H%M%S")
        self.base = Path(f"results/{self.target}_{ts}")
        self.recon = self.base / "recon"
        self.scans = self.base / "scans"
        self.reports = self.base / "reports"

        for d in [self.recon, self.scans, self.reports]:
            d.mkdir(parents=True, exist_ok=True)

        self.summary = {"target": self.target}

    # ================= UTIL =================

    def run(self, cmd, stdin=None):
        try:
            r = subprocess.run(cmd, input=stdin, text=True, capture_output=True)
            return r.stdout.strip()
        except Exception:
            return ""

    def tool(self, name):
        return shutil.which(name) is not None

    def write(self, path, content):
        path.write_text(content if content else "")

    # ================= MODULES =================

    def asn(self):
        if self.tool("asnmap"):
            self.write(self.recon / "asn.txt",
                       self.run(["asnmap", "-d", self.target]))

    def whois(self):
        if self.tool("whois"):
            self.write(self.recon / "whois.txt",
                       self.run(["whois", self.target]))

    def subdomains(self):
        subs = set()
        for c in [
            ["subfinder", "-d", self.target, "-silent"],
            ["assetfinder", "--subs-only", self.target],
            ["amass", "enum", "-passive", "-d", self.target]
        ]:
            subs |= set(self.run(c).splitlines())

        self.subs = sorted(subs)
        self.write(self.recon / "subdomains.txt", "\n".join(self.subs))

    def dns(self):
        def resolve(s):
            out = self.run(["dnsx", "-a", "-resp-only", "-silent"], stdin=s) \
                if self.tool("dnsx") else self.run(["dig", "+short", s])
            return {i for i in out.splitlines()
                    if re.match(r"\d+\.\d+\.\d+\.\d+", i)}

        ips = set()
        with ThreadPoolExecutor(MAX_WORKERS) as exe:
            for f in tqdm(as_completed([exe.submit(resolve, s) for s in self.subs]),
                          total=len(self.subs), desc="DNS Resolution"):
                ips |= f.result()

        self.ips = sorted(ips)
        self.write(self.recon / "domain_ips.txt", "\n".join(self.ips))

    def alive(self):
        self.alive_domains = self.recon / "alive_domains.txt"
        if not self.tool("httpx"):
            print("[!] httpx not installed, skipping live-host probing")
            self.alive_domains.touch()  # keep an empty file for later steps
            return
        with self.alive_domains.open("w") as out:
            subprocess.run(
                ["httpx", "-l", str(self.recon / "subdomains.txt"), "-silent"],
                stdout=out,
            )

    def cdn(self):
        self.write(self.recon / "cdn_origin.txt",
                   self.run(["httpx", "-l", self.alive_domains,
                             "-cdn", "-cname", "-ip", "-silent"]))

    def waf(self):
        if not self.tool("wafw00f"):
            return
        out = []
        for s in self.subs:
            out.append(f"[{s}]\n{self.run(['wafw00f', s])}")
        self.write(self.recon / "waf.txt", "\n".join(out))

    def tech(self):
        self.write(self.recon / "technologies_httpx.txt",
                   self.run(["httpx", "-l", self.alive_domains,
                             "-tech-detect", "-title", "-server", "-silent"]))

    def tls(self):
        if not self.tool("sslscan"):
            return
        out = []
        for s in self.subs:
            out.append(f"==== {s} ====\n{self.run(['sslscan', '--no-colour', s])}")
        self.write(self.recon / "tls.txt", "\n".join(out))

    def auth_api(self):
        auth, api = set(), set()
        for s in self.subs:
            for a in ["login", "signin", "admin", "reset"]:
                auth.add(f"https://{s}/{a}")
            for p in ["/api", "/api/v1", "/swagger", "/graphql"]:
                api.add(f"https://{s}{p}")

        self.write(self.recon / "auth_surface.txt", "\n".join(sorted(auth)))
        self.write(self.recon / "api_endpoints.txt", "\n".join(sorted(api)))

    def historical(self):
        if self.tool("waybackurls"):
            self.write(self.recon / "historical_urls.txt",
                       self.run(["waybackurls", self.target]))
        elif self.tool("gau"):
            self.write(self.recon / "historical_urls.txt",
                       self.run(["gau", "--subs", self.target]))

    def google_dorks(self):
        dorks = [
            f"site:{self.target} ext:env",
            f"site:{self.target} ext:log",
            f"site:{self.target} ext:sql",
            f"site:{self.target} \"index of\"",
            f"site:{self.target} inurl:admin",
            f"site:{self.target} inurl:login",
            f"site:{self.target} inurl:api"
        ]
        self.write(self.recon / "google_dorks.txt", "\n".join(dorks))

    def crawl(self):
        if self.args.crawl and self.tool("katana"):
            self.write(self.recon / "crawled_urls.txt",
                       self.run(["katana", "-list", self.alive_domains, "-silent"]))

    def dirs(self):
        if self.args.dirs and self.tool("feroxbuster"):
            self.write(self.recon / "directories.txt",
                       self.run(["feroxbuster", "-u",
                                 f"file://{self.alive_domains}", "-q"]))

    def harvester(self):
        if not self.tool("theHarvester"):
            return
        raw = self.run(["theHarvester", "-d", self.target,
                        "-b", "bing,duckduckgo"])
        self.write(self.recon / "harvester_raw.txt", raw)

    # ================= SECURITY HEADERS =================

    def security_headers(self):
        headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy"
        ]

        if not self.tool("httpx") or not self.alive_domains.exists():
            return

        results = []
        for url in open(self.alive_domains):
            raw = self.run(["httpx", "-u", url.strip(),
                            "-headers", "-silent"])
            found = {h: "missing" for h in headers}
            for line in raw.splitlines():
                for h in headers:
                    if line.lower().startswith(h):
                        found[h] = line.split(":", 1)[1].strip()
            results.append({"url": url.strip(), "headers": found})

        self.write(self.recon / "security_headers_raw.json",
                   json.dumps(results, indent=2))

    # ================= WHATWEB =================

    def whatweb(self):
        if not self.tool("whatweb"):
            print("[!] whatweb not installed, skipping")
            return

        raw_json = self.recon / "whatweb_raw.json"
        readable = self.recon / "whatweb_tech.txt"

        subprocess.run([
            "whatweb", "-a", "3",
            "--log-json", raw_json,
            "-i", self.alive_domains
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        parsed = {}
        for line in raw_json.read_text().splitlines():
            try:
                j = json.loads(line)
                parsed[j.get("target")] = sorted(j.get("plugins", {}).keys())
            except:
                pass

        out = []
        for url, techs in parsed.items():
            out.append(f"==== {url} ====")
            for t in techs:
                out.append(f"- {t}")
            out.append("")

        self.write(readable, "\n".join(out))

    # ================= VULNERABILITY SCAN =================

    def vuln(self):
        """Run nuclei against live hosts, emitting JSONL for ASM ingestion."""
        alive = self.recon / "alive_domains.txt"
        if not alive.exists() or not alive.read_text(errors="ignore").strip():
            return
        try:
            from asm.vuln import run_nuclei  # local import keeps recon standalone
        except Exception:
            if self.tool("nuclei"):
                subprocess.run([
                    "nuclei", "-l", str(alive), "-jsonl",
                    "-o", str(self.recon / "nuclei.jsonl"),
                    "-severity", "critical,high,medium,low",
                    "-silent", "-no-color",
                ])
            return
        run_nuclei(
            targets_file=alive,
            output_file=self.recon / "nuclei.jsonl",
            severities=["critical", "high", "medium", "low"],
        )

    # ================= SCAN =================

    def scan(self):
        if not self.ips:
            return
        if not self.tool("nmap"):
            print("[!] nmap not installed, skipping port scan")
            return
        tgt = self.scans / "targets.txt"
        self.write(tgt, "\n".join(self.ips))
        subprocess.run([
            "nmap", "-Pn", "-sC", "-sV",
            "-iL", str(tgt), "-oA", str(self.scans / "nmap")
        ])

    # ================= RUN =================

    def run_all(self):
        pipeline = [
            self.asn,
            self.whois,
            self.subdomains,
            self.dns,
            self.alive,
            self.cdn,
            self.waf,
            self.tech,
            self.tls,
            self.security_headers,
            self.whatweb,
            self.auth_api,
            self.historical,
            self.google_dorks,
            self.crawl,
            self.dirs,
            self.harvester,
            self.scan,
            self.vuln
        ]

        self.preflight()

        for step in pipeline:
            print(f"[+] {step.__name__}")
            try:
                step()
            except Exception as exc:  # a broken/missing tool must not abort the pass
                print(f"[!] step '{step.__name__}' failed: {exc} (continuing)")

        print("\n[✓] Recon completed")

    # Tools the pipeline drives; missing ones are skipped, not fatal.
    EXPECTED_TOOLS = [
        "subfinder", "assetfinder", "amass", "dnsx", "httpx", "nmap",
        "nuclei", "whatweb", "sslscan", "wafw00f", "asnmap", "whois",
        "waybackurls", "gau", "katana", "feroxbuster", "theHarvester",
    ]

    def preflight(self):
        missing = [t for t in self.EXPECTED_TOOLS if not self.tool(t)]
        if missing:
            print(f"[!] {len(missing)}/{len(self.EXPECTED_TOOLS)} recon tools "
                  f"not found: {', '.join(missing)}")
            print("[!] Those stages will be skipped. Install the toolchain with "
                  "`sudo ./setup.sh` for full coverage.\n")

# ================= ENTRY =================

def main():
    banner()
    args = parse_args()
    ReconEngine(args).run_all()


if __name__ == "__main__":
    main()
