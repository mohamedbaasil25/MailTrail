import dns.resolver
import logging
import asyncio

logger = logging.getLogger(__name__)

def verify_spf(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=2.0)
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode('utf-8')
            if txt_string.startswith('v=spf1'):
                return "PASS"
        return "FAIL"
    except dns.exception.Timeout:
        logger.warning(f"SPF lookup TIMEOUT for {domain}")
        return "TIMEOUT"
    except Exception as e:
        logger.warning(f"SPF lookup failed for {domain}: {e}")
        return "UNKNOWN"

def verify_dmarc(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=2.0)
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode('utf-8')
            if txt_string.startswith('v=DMARC1'):
                return "PASS"
        return "FAIL"
    except dns.exception.Timeout:
        logger.warning(f"DMARC lookup TIMEOUT for {domain}")
        return "TIMEOUT"
    except Exception as e:
        logger.warning(f"DMARC lookup failed for {domain}: {e}")
        return "UNKNOWN"

async def validate_domain_auth_async(domain: str) -> dict:
    if not domain:
        return {"spf_valid": False, "dmarc_valid": False}
    
    # Run synchronous DNS lookups in a separate thread to prevent blocking
    spf_result = await asyncio.to_thread(verify_spf, domain)
    dmarc_result = await asyncio.to_thread(verify_dmarc, domain)
    
    return {
        "spf_valid": spf_result == "PASS",
        "dmarc_valid": dmarc_result == "PASS",
        "spf_status": spf_result,
        "dmarc_status": dmarc_result
    }
