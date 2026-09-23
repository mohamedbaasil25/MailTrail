import re
from typing import List, Dict

class ThreatIntelService:
    def __init__(self):
        # Mock database of known bad indicators
        self.known_bad_domains = {
            "evil-phishing-site.com",
            "secure-login-verify.net",
            "account-update-urgent.com"
        }
        self.known_bad_ips = {
            "203.0.113.42",
            "198.51.100.10",
            "192.0.2.1"
        }

    def extract_domains(self, text: str) -> List[str]:
        """Extract domain names from URLs in text."""
        domain_pattern = r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        return list(set(re.findall(domain_pattern, text)))

    def extract_ips(self, text: str) -> List[str]:
        """Extract IPv4 addresses from text."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))

    def check_indicators(self, text: str) -> List[Dict]:
        """Checks text for known bad domains and IPs."""
        signals = []
        
        domains = self.extract_domains(text)
        for domain in domains:
            if domain.lower() in self.known_bad_domains:
                signals.append({
                    "title": "Threat Intel (Domain)",
                    "detail": f"Domain '{domain}' is known malicious.",
                    "points": 60.0
                })
                
        ips = self.extract_ips(text)
        for ip in ips:
            if ip in self.known_bad_ips:
                signals.append({
                    "title": "Threat Intel (IP)",
                    "detail": f"IP '{ip}' is associated with malicious activity.",
                    "points": 70.0
                })
                
        return signals

threat_intel_service = ThreatIntelService()
