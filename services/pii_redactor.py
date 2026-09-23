import re

def redact_pii(text: str) -> str:
    """
    Redacts sensitive Personally Identifiable Information (PII) from the given text.
    Currently masks Social Security Numbers and Credit Card numbers.
    """
    if not text:
        return text
        
    # Mask SSN (XXX-XX-XXXX)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    text = re.sub(ssn_pattern, 'XXX-XX-XXXX', text)
    
    # Mask Credit Card (XXXX-XXXX-XXXX-XXXX)
    cc_pattern = r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'
    text = re.sub(cc_pattern, 'XXXX-XXXX-XXXX-XXXX', text)
    
    return text
