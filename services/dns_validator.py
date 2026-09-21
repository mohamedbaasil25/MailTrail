import dns.resolver
import logging

logger = logging.getLogger(__name__)

def verify_spf(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode('utf-8')
            if txt_string.startswith('v=spf1'):
                return True
    except Exception as e:
        logger.warning(f"SPF lookup failed for {domain}: {e}")
    return False

def verify_dmarc(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode('utf-8')
            if txt_string.startswith('v=DMARC1'):
                return True
    except Exception as e:
        logger.warning(f"DMARC lookup failed for {domain}: {e}")
    return False

def validate_domain_auth(domain: str) -> dict:
    if not domain:
        return {"spf_valid": False, "dmarc_valid": False}
    
    spf_valid = verify_spf(domain)
    dmarc_valid = verify_dmarc(domain)
    
    return {
        "spf_valid": spf_valid,
        "dmarc_valid": dmarc_valid
    }
