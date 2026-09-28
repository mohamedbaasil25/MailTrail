"""
Unit tests for services.threat_intel_service. These mock out
services.http_client.fetch_json entirely - no real network calls - so the
suite stays fast and doesn't depend on (or burn quota against) a live
VirusTotal-compatible API.
"""

import pytest

from services.threat_intel_service import ThreatIntelService
from services.http_client import APIClientError, APIRequestError


def make_service(monkeypatch, api_key="test-key", max_indicators=5):
    service = ThreatIntelService()
    service.api_key = api_key
    service.is_available = bool(api_key)
    service.max_indicators = max_indicators
    return service


def test_no_api_key_reports_unavailable(monkeypatch):
    service = make_service(monkeypatch, api_key="")
    result = service.check_indicators("Visit http://totally-fine.com now")
    assert result == {"status": "unavailable", "signals": []}


def test_no_indicators_in_text_is_available_with_no_signals(monkeypatch):
    service = make_service(monkeypatch)
    result = service.check_indicators("No links or IPs in this message at all.")
    assert result == {"status": "available", "signals": []}


def test_malicious_domain_produces_signal(monkeypatch):
    service = make_service(monkeypatch)

    def fake_fetch_json(url, **kwargs):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 0}}}}

    monkeypatch.setattr("services.threat_intel_service.fetch_json", fake_fetch_json)

    result = service.check_indicators("Click http://evil-phish.example now")
    assert result["status"] == "available"
    assert len(result["signals"]) == 1
    assert result["signals"][0]["title"] == "Threat Intel"
    assert "malicious" in result["signals"][0]["detail"]


def test_clean_domain_produces_no_signal(monkeypatch):
    service = make_service(monkeypatch)

    def fake_fetch_json(url, **kwargs):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}

    monkeypatch.setattr("services.threat_intel_service.fetch_json", fake_fetch_json)

    result = service.check_indicators("Click http://totally-fine.example now")
    assert result == {"status": "available", "signals": []}


def test_provider_down_reports_degraded_not_unavailable(monkeypatch):
    """
    A configured-but-unreachable provider must be distinguishable from
    "never configured" - callers (and the frontend) shouldn't confuse a
    real outage with the feature being off.
    """
    service = make_service(monkeypatch)

    def always_fails(url, **kwargs):
        raise APIRequestError("provider unreachable after retries")

    monkeypatch.setattr("services.threat_intel_service.fetch_json", always_fails)

    result = service.check_indicators("Click http://some-domain.example now")
    assert result == {"status": "degraded", "signals": []}


def test_client_error_on_one_indicator_does_not_abort_others(monkeypatch):
    service = make_service(monkeypatch)
    calls = []

    def fake_fetch_json(url, **kwargs):
        calls.append(url)
        if "bad-key-domain" in url:
            raise APIClientError("401 unauthorized")
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 0}}}}

    monkeypatch.setattr("services.threat_intel_service.fetch_json", fake_fetch_json)

    result = service.check_indicators(
        "See http://bad-key-domain.example and http://second-domain.example"
    )
    assert len(calls) == 2  # both indicators were attempted
    assert result["status"] == "available"  # the second one succeeded
    assert len(result["signals"]) == 1  # only the successful, malicious one


def test_max_indicators_caps_external_calls(monkeypatch):
    service = make_service(monkeypatch, max_indicators=2)
    calls = []

    def fake_fetch_json(url, **kwargs):
        calls.append(url)
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}

    monkeypatch.setattr("services.threat_intel_service.fetch_json", fake_fetch_json)

    text = " ".join(f"http://domain{i}.example" for i in range(10))
    service.check_indicators(text)
    assert len(calls) == 2
