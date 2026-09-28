import logging
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# Single shared rate limiter instance used across the entire application.
# This MUST be the same instance attached to app.state.limiter in main.py.
#
# By default this uses slowapi's in-memory storage, which counts requests
# per-process. That's correct for a single instance, but silently WRONG the
# moment this runs as more than one process (multiple gunicorn workers, or
# multiple replicas behind a load balancer): each process keeps its own
# counter, so e.g. a "5 requests/minute" limit actually becomes "5 * worker
# count" per minute, and an attacker hitting different workers/instances
# never even sees a consistent limit. Setting RATE_LIMIT_STORAGE_URI to a
# shared backend (currently Redis) fixes that by making every worker/
# instance share the same counters.
_storage_uri = os.getenv("RATE_LIMIT_STORAGE_URI")

if _storage_uri:
    limiter = Limiter(key_func=get_remote_address, storage_uri=_storage_uri)
    logger.info("Rate limiter using shared storage backend (safe for multiple workers/instances).")
else:
    limiter = Limiter(key_func=get_remote_address)
    if os.getenv("ENV") == "production":
        logger.warning(
            "RATE_LIMIT_STORAGE_URI is not set - rate limits are being tracked "
            "in-memory, per-process. If this deployment runs more than one "
            "worker or instance, effective rate limits are higher than "
            "configured and inconsistent across requests. Set "
            "RATE_LIMIT_STORAGE_URI=redis://... for correct behavior at scale."
        )
