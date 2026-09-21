import re
from urllib.parse import urlparse

URGENCY_RE = re.compile(r'\b(urgent|immediately|act now|action required|verify now|account (will be |is )?suspend|final notice|within 24 hours|expires? (today|soon)|turant|khata band)\b', re.IGNORECASE)
LURE_RE = re.compile(r'\b(password|login|sign[- ]?in|verify|otp|one[- ]time pass|credential|bank account|card number|cvv|payment|invoice overdue|update your billing)\b', re.IGNORECASE)
RISKY_EXT_RE = re.compile(r'\.(exe|scr|js|vbs|bat|cmd|zip|rar|iso|lnk|docm|xlsm|pptm|jar)(\s|"|\'|<|$)', re.IGNORECASE)

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".support", ".gq", ".work", ".mov", ".loan"]
BRANDS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "uidai", "incometax", "indiapost", "npci", "google", "microsoft", "paypal", "amazon", "apple", "netflix"]

def extract_urls(text: str) -> list:
    return re.findall(r'https?:\/\/[^\s<>"\'\]]+', text, re.IGNORECASE)

def domain_of(url: str) -> str:
    try:
        return urlparse(url).hostname.lower()
    except Exception:
        m = re.match(r'^https?:\/\/([^/]+)', url, re.IGNORECASE)
        return m.group(1).lower() if m else ""

def is_ip_literal_host(host: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))

def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def brand_lookalike(host: str):
    core = host.replace("www.", "").split(".")[0]
    for brand in BRANDS:
        if core == brand:
            continue
        if brand in core or levenshtein(core, brand) <= 1:
            return brand
    return None

def score_heuristics(text: str):
    lower_text = text.lower()
    signals = []
    score = 6.0
    
    def add(points, title, detail):
        nonlocal score
        score += points
        signals.append({"title": title, "detail": detail, "points": points})

    if URGENCY_RE.search(lower_text):
        add(15, "Urgency language", "The message uses pressure language designed to short-circuit careful review.")
    if LURE_RE.search(lower_text):
        add(18, "Credential or payment lure", "The message asks for, or references, a credential, OTP, or payment action.")
        
    urls = extract_urls(text)
    http_urls = [u for u in urls if u.lower().startswith("http://")]
    if http_urls:
        add(10, "Insecure link", f"{len(http_urls)} link(s) use unencrypted HTTP instead of HTTPS.")
    if len(urls) == 1:
        add(10, "External link", "One external destination requires reputation and target-page verification.")
    if len(urls) >= 2:
        add(16, "Multiple external links", f"{len(urls)} distinct destinations widen the investigation surface.")
        
    saw_shortener = False
    saw_ip_literal = False
    saw_suspicious_tld = False
    lookalike_brand = None
    
    for u in urls:
        host = domain_of(u)
        if not host:
            continue
        if any(host.endswith(s) for s in SHORTENERS):
            saw_shortener = True
        if is_ip_literal_host(host):
            saw_ip_literal = True
        if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            saw_suspicious_tld = True
        bl = brand_lookalike(host)
        if bl and not lookalike_brand:
            lookalike_brand = {"brand": bl, "host": host}
            
    if saw_shortener:
        add(12, "Link shortener", "A shortening service hides the true destination until the link is clicked.")
    if saw_ip_literal:
        add(16, "IP-literal destination", "A link points directly at a numeric address rather than a named domain.")
    if saw_suspicious_tld:
        add(9, "Suspicious top-level domain", "One destination uses a low-cost TLD commonly abused in campaigns.")
    if lookalike_brand:
        add(20, "Brand look-alike domain", f'"{lookalike_brand["host"]}" reads as {lookalike_brand["brand"].upper()} but doesn\'t match its official domain.')
        
    if RISKY_EXT_RE.search(text):
        add(18, "High-risk attachment type", "A referenced file extension is commonly used to deliver malicious payloads.")
        
    from_m = re.search(r'^from:\s*.*?<?([\w.+-]+@[\w.-]+)>?', text, re.IGNORECASE | re.MULTILINE)
    reply_m = re.search(r'^reply-to:\s*.*?<?([\w.+-]+@[\w.-]+)>?', text, re.IGNORECASE | re.MULTILINE)
    if from_m and reply_m:
        from_domain = from_m.group(1).split("@")[-1].lower()
        reply_domain = reply_m.group(1).split("@")[-1].lower()
        if from_domain != reply_domain:
            add(9, "From / Reply-To mismatch", f"Replies are redirected from {from_domain} to {reply_domain}.")

    return {"score": min(max(score, 0), 100), "signals": signals, "urls": urls}

heuristic_engine = score_heuristics
