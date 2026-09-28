import re

def redact_pii(text: str) -> str:
    """
    Redacts sensitive Personally Identifiable Information (PII) from the given text.
    Currently masks Social Security Numbers, Credit Card numbers, Phone numbers,
    IP addresses, and URLs.
    """
    if not text:
        return text
        
    # Mask SSN (XXX-XX-XXXX)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    text = re.sub(ssn_pattern, '[REDACTED_SSN]', text)
    
    # Mask Credit Card (XXXX-XXXX-XXXX-XXXX)
    cc_pattern = r'\b(?:\d{4}[ -]?){3}\d{4}\b'
    text = re.sub(cc_pattern, '[REDACTED_CC]', text)
    
    # Mask Phone Numbers (basic formats)
    phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    text = re.sub(phone_pattern, '[REDACTED_PHONE]', text)
    
    # Mask IPv4 Addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    text = re.sub(ip_pattern, '[REDACTED_IP]', text)
    
    # Mask Email Addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    text = re.sub(email_pattern, '[REDACTED_EMAIL]', text)
    
    # Mask URLs (HTTP/HTTPS)
    url_pattern = r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
    text = re.sub(url_pattern, '[REDACTED_URL]', text)
    
    return text
