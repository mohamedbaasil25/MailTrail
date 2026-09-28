#!/usr/bin/env python3
"""
scripts/docker_healthcheck.py

Used by the Dockerfile's HEALTHCHECK instruction. Hits the readiness
endpoint (which pings MongoDB - see api/routes.py's /health) rather than
just checking "is the process alive", so `docker ps` and orchestrators
relying on container health actually reflect whether the app can serve
real traffic. Exits 0 on HTTP 200, 1 otherwise (including on any
connection error/timeout) - that's the contract Docker's HEALTHCHECK
expects.
"""

import os
import sys
import urllib.request
import urllib.error

port = os.environ.get("PORT", "8000")
url = f"http://127.0.0.1:{port}/api/v1/health"

try:
    with urllib.request.urlopen(url, timeout=3) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except (urllib.error.URLError, OSError):
    sys.exit(1)
