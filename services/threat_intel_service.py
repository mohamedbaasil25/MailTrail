import re
import logging
from typing import List, Dict

from config import settings
from services.http_client import fetch_json, APIClientError, APIRequestError

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Looks up domains/IPs extracted from an email against an external
    threat-intelligence provider (VirusTotal v3 API by default - any
    provider exposing a compatible /domains/{id} and /ip_addresses/{id}
    JSON shape can be swapped in via THREAT_INTEL_BASE_URL).

    Degrades gracefully: if the API key isn't configured, or every call to
    the provider fails (down, rate-limited past retries, network issue),
    this returns status="unavailable"/"degraded" rather than raising - a
    flaky third-party API should never take down email analysis.
    """

    def __init__(self):
        self.api_key = settings.threat_intel_api_key
        self.base_url = settings.threat_intel_base_url.rstrip("/")
        self.timeout = settings.threat_intel_timeout_seconds
        self.max_retries = settings.threat_intel_max_retries
        self.max_indicators = settings.threat_intel_max_indicators
        self.is_available = bool(self.api_key)

    def extract_domains(self, text: str) -> List[str]:
        """Extract domain names from URLs in text."""
        domain_pattern = r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        return list(set(re.findall(domain_pattern, text)))

    def extract_ips(self, text: str) -> List[str]:
        """Extract IPv4 addresses from text."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def _lookup_domain(self, domain: str) -> Dict:
        return fetch_json(
            f"{self.base_url}/domains/{domain}",
            headers=self._headers(),
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

    def _lookup_ip(self, ip: str) -> Dict:
        return fetch_json(
            f"{self.base_url}/ip_addresses/{ip}",
            headers=self._headers(),
            timeout=self.timeout,
            max_retries=self.max_retries,
        )

    def _signal_from_verdict(self, indicator: str, kind: str, data: Dict) -> Dict:
        """Turns a VirusTotal-shaped response into a {title, detail, points} signal."""
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            return {
                "title": "Threat Intel",
                "detail": f"{kind.capitalize()} '{indicator}' flagged malicious by {malicious} security vendor(s).",
                "points": min(40.0, 15.0 + malicious * 2.0),
            }
        if suspicious > 0:
            return {
                "title": "Threat Intel",
                "detail": f"{kind.capitalize()} '{indicator}' flagged suspicious by {suspicious} security vendor(s).",
                "points": min(20.0, 5.0 + suspicious * 2.0),
            }
        return None  # clean - no signal to raise

    def check_indicators(self, text: str) -> dict:
        """
        Checks text for known-bad domains and IPs via the configured
        threat-intel provider.

        Returns: {"status": "available" | "degraded" | "unavailable", "signals": [...]}
        - "unavailable": no API key configured (nothing was attempted).
        - "degraded": configured, but every lookup attempted failed (API
          down/rate-limited/misconfigured) - signals will be empty, callers
          should not treat this the same as "confirmed clean".
        - "available": at least one lookup succeeded; signals reflect what
          the provider actually returned (may still be empty if clean).
        """
        if not self.is_available:
            return {"status": "unavailable", "signals": []}

        indicators = (
            [("domain", d) for d in self.extract_domains(text)]
            + [("ip", i) for i in self.extract_ips(text)]
        )[: self.max_indicators]

        if not indicators:
            return {"status": "available", "signals": []}

        signals = []
        successes = 0
        for kind, indicator in indicators:
            try:
                lookup = self._lookup_domain if kind == "domain" else self._lookup_ip
                data = lookup(indicator)
                successes += 1
                signal = self._signal_from_verdict(indicator, kind, data)
                if signal:
                    signals.append(signal)
            except APIClientError as exc:
                # e.g. bad API key (401/403) or unknown indicator (404) -
                # not this specific email's fault; log and move on to the
                # next indicator rather than failing the whole analysis.
                logger.warning("Threat intel client error for %s '%s': %s", kind, indicator, exc)
            except APIRequestError as exc:
                logger.warning("Threat intel provider unreachable for %s '%s': %s", kind, indicator, exc)

        if successes == 0:
            return {"status": "degraded", "signals": []}
        return {"status": "available", "signals": signals}


threat_intel_service = ThreatIntelService()
