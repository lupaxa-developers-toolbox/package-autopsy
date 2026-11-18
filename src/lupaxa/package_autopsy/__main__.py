"""Allow ``python -m lupaxa.package_autopsy``."""

from __future__ import annotations

from lupaxa.package_autopsy.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
