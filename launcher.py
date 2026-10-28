"""PyInstaller entry point (no embedded credentials)."""

import sys
from tamaru.__main__ import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Tamaru: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
