"""Enable `python -m asm <command>` (used by the web UI to launch scan jobs)."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
