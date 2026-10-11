"""
ReconEngine ASM – Attack Surface Management & Vulnerability Scanning.

This package turns the ReconEngine recon framework into a continuous
Attack Surface Management (ASM) platform:

  * persistent asset inventory (SQLite) that tracks assets over time
  * change detection / diffing between scans ("what is new?")
  * integrated vulnerability scanning (nuclei)
  * alerting on new assets and new findings
  * continuous monitoring (scheduled re-scans)

Authorized security testing only.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
