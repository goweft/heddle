#!/usr/bin/env python3
"""Heddle Web Dashboard.

Entry point: `heddle-dashboard` (registered in pyproject.toml).
"""
import sys

import uvicorn

from heddle.web.api import create_app


def main():
    app = create_app()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8300
    print(f"\n  Heddle Dashboard: http://0.0.0.0:{port}\n")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
