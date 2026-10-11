"""
Vulnerability scanning via nuclei.

nuclei is the engine ReconEngine's ``setup.sh`` already installs; this module
drives it against the live hosts discovered during recon and writes JSONL output
that :mod:`asm.ingest` turns into tracked findings.

Authorized security testing only — nuclei actively probes the target.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from .ingest import parse_nuclei_jsonl
from .models import Finding

# Default severities to report. Raising the floor keeps continuous monitoring
# signal-to-noise high; override via config / CLI.
DEFAULT_SEVERITIES = ["critical", "high", "medium", "low"]


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei(
    targets_file: Path,
    output_file: Path,
    severities: Optional[List[str]] = None,
    rate_limit: int = 150,
    timeout: int = 5,
    extra_args: Optional[List[str]] = None,
    templates: Optional[str] = None,
) -> List[Finding]:
    """Run nuclei against the hosts listed in ``targets_file``.

    Returns parsed findings and leaves JSONL at ``output_file`` for ingestion.
    Returns an empty list (never raises) if nuclei is missing or the input
    file is empty.
    """
    if not nuclei_available():
        print("[!] nuclei not installed – skipping vulnerability scan")
        return []
    if not targets_file.exists() or not targets_file.read_text(errors="ignore").strip():
        print("[!] no live hosts to scan – skipping vulnerability scan")
        return []

    severities = severities or DEFAULT_SEVERITIES
    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_file),
        "-severity", ",".join(severities),
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-silent",
        "-no-color",
    ]
    if templates:
        cmd += ["-t", templates]
    if extra_args:
        cmd += extra_args

    print(f"[+] Running nuclei: severities={','.join(severities)}")
    try:
        subprocess.run(cmd, check=False)
    except OSError as exc:
        print(f"[!] nuclei execution failed: {exc}")
        return []

    if not output_file.exists():
        return []
    return parse_nuclei_jsonl(output_file.read_text(errors="ignore"))


def update_templates() -> None:
    """Refresh the nuclei template store (best effort)."""
    if not nuclei_available():
        return
    try:
        subprocess.run(["nuclei", "-update-templates", "-silent"], check=False)
    except OSError:
        pass
