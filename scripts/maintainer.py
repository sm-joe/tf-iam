#!/usr/bin/env python3
"""Repository-only audit entry point; not an installed CLI command."""
from tfiam.cli import main
if __name__=="__main__":
    raise SystemExit(main(maintainer=True))
