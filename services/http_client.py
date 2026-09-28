"""
services/http_client.py

Shared HTTP fetch helper with retry logic for calling external APIs
(currently: the threat-intelligence provider in services/threat_intel_service.py).
Retries transient failures with exponential backoff + full jitter; fails
fast on non-retryable client errors so a bad API key or an unknown
indicator doesn't burn through retry attempts for no reason.

This is intentionally synchronous (uses `requests`, not `httpx`/`aiohttp`).
Callers running inside an async request handler MUST invoke it via
`asyncio.to_thread(...)` rather than calling it directly - see
threat_intel_service.check_indicators() and its call site in api/routes.py
for the pattern. Calling it directly from an `async def` would block the
whole event loop for the duration of every request + backoff sleep.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class APIRequestError(Exception):
    """Raised when a request fails after all retries are exhausted."""


class APIClientError(Exception):
    """Raised immediately for non-retryable client errors (4xx other than 429)."""


# 429 (rate limited) and 5xx (server-side issues) are worth retrying.
# Everything else in the 4xx range is the caller's fault (bad request, bad
# API key, unknown resource) - retrying it would just waste attempts.
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _compute_backoff(attempt: int, base_delay: float, max_delay: float) -> float:
    """
    Exponential backoff with "full jitter": a random delay between 0 and the
    theoretical exponential ceiling for this attempt. Full jitter avoids many
    failed callers retrying in lockstep and re-overwhelming the API at the
    same instant.
    """
    ceiling = min(max_delay, base_delay * (2 ** attempt))
    # Non-cryptographic jitter for retry timing only - never used for any
    # security-sensitive value.
    return random.uniform(0, ceiling)  # nosec B311


def _request_with_retry(
    url: str,
    *,
    method: str = "GET",
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    auth: Optional[tuple] = None,
    timeout: float = 10.0,
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
) -> "requests.Response":
    """
    Shared retry core: performs the request, retries transient failures with
    backoff, and returns the raw Response on success. fetch_json() and
    fetch_bytes() are both thin wrappers around this that just decide how to
    interpret the body (parsed JSON vs raw bytes).
    """
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries + 1):  # +1 for the initial attempt
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                json=json_body,
                auth=auth,
                timeout=timeout,
            )

            if response.status_code in RETRYABLE_STATUS_CODES:
                last_exception = requests.exceptions.HTTPError(
                    f"Retryable status {response.status_code} from {url}"
                )
                logger.warning(
                    "Attempt %d/%d: retryable status %d from %s",
                    attempt + 1, max_retries + 1, response.status_code, url,
                )
            elif 400 <= response.status_code < 500:
                raise APIClientError(
                    f"Client error {response.status_code} from {url}: {response.text[:300]}"
                )
            else:
                response.raise_for_status()
                return response

        except APIClientError:
            raise  # already logged; nothing more to do, don't retry

        except requests.exceptions.Timeout as exc:
            last_exception = exc
            logger.warning("Attempt %d/%d: timeout calling %s", attempt + 1, max_retries + 1, url)

        except requests.exceptions.ConnectionError as exc:
            last_exception = exc
            logger.warning("Attempt %d/%d: connection error calling %s", attempt + 1, max_retries + 1, url)

        except requests.exceptions.RequestException as exc:
            last_exception = exc
            logger.warning("Attempt %d/%d: request error calling %s: %s", attempt + 1, max_retries + 1, url, exc)

        if attempt < max_retries:
            delay = _compute_backoff(attempt, base_delay, max_delay)
            logger.info("Retrying %s in %.2fs...", url, delay)
            time.sleep(delay)

    raise APIRequestError(
        f"Failed to fetch {url} after {max_retries + 1} attempts"
    ) from last_exception


def fetch_json(
    url: str,
    *,
    method: str = "GET",
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    timeout: float = 10.0,
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
) -> Any:
    """
    Fetch JSON from an API with automatic retry on transient failures.

    Raises:
        APIClientError: immediately, for non-retryable 4xx responses.
        APIRequestError: if every retry attempt is exhausted.
    """
    response = _request_with_retry(
        url, method=method, params=params, headers=headers, json_body=json_body,
        timeout=timeout, max_retries=max_retries, base_delay=base_delay, max_delay=max_delay,
    )
    return response.json()


def fetch_bytes(
    url: str,
    *,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    auth: Optional[tuple] = None,
    timeout: float = 30.0,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 15.0,
) -> bytes:
    """
    Fetch raw bytes (e.g. a binary download like a .tar.gz) with the same
    retry/backoff behavior as fetch_json(). Used by
    scripts/update_geoip_db.py to download the MaxMind GeoLite2 database.

    Raises:
        APIClientError: immediately, for non-retryable 4xx responses.
        APIRequestError: if every retry attempt is exhausted.
    """
    response = _request_with_retry(
        url, method="GET", params=params, headers=headers, auth=auth,
        timeout=timeout, max_retries=max_retries, base_delay=base_delay, max_delay=max_delay,
    )
    return response.content
