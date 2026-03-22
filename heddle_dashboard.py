#!/usr/bin/env python3
"""Heddle Web Dashboard launcher."""
import sys
sys.path.insert(0, "/mnt/workspace/projects/loom/src")

import uvicorn
from heddle.web.api import create_app

app = create_app()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8300
    print(f"\n  Heddle Dashboard: http://0.0.0.0:{port}\n")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
