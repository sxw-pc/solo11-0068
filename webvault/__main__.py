"""Allow ``python -m webvault`` from an uninstalled source checkout."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
