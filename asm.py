#!/usr/bin/env python3
"""
ReconEngine ASM – entry point.

Usage examples:
    python3 asm.py scan -t example.com
    python3 asm.py scan -t example.com --crawl --dirs --slack-webhook https://...
    python3 asm.py watch -t example.com --interval 720
    python3 asm.py findings -t example.com --min-severity high
    python3 asm.py report -t example.com -o report.html

Authorized security testing only.
"""

from asm.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
