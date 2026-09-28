import re
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List

# Matches the bare address inside "Display Name <addr@domain>" style headers.
_ANGLE_ADDR_RE = re.compile(r'<([^<>\s]+@[^<>\s]+)>')
# Deliberately permissive - this only needs to catch obviously-malformed
# values (empty strings, missing '@', embedded whitespace/angle-brackets
# that survived normalization); it is not a full RFC 5322 validator, since
# real-world "From:" headers are messier than the spec and a stricter regex
# (or pydantic's EmailStr) would reject legitimate inputs this tool needs
# to accept and analyze rather than bounce.
_LOOSE_EMAIL_RE = re.compile(r'^[^\s@<>]+@[^\s@<>]+$')

def normalize_email_address(value: Optional[str]) -> Optional[str]:
    """
    Extracts the bare email address from an RFC 5322 "Display Name <addr>"
    string, e.g. '"PayPal Support" <security@paypa1-secure.top>' ->
    'security@paypa1-secure.top'. If no angle-bracket address is present,
    the input is returned stripped and unchanged. This mirrors the
    extraction already used by services.imap_client so the manual/API
    ingestion path and the automated IMAP path behave identically -
    without it, a raw "From:" header on this path corrupts every downstream
    SPF/DMARC domain lookup with a stray '>' character.
    """
    if value is None:
        return value
    value = value.strip()
    match = _ANGLE_ADDR_RE.search(value)
    return match.group(1) if match else value

class EmailHeader(BaseModel):
    name: str
    value: str

class EmailData(BaseModel):
    """
    Model representing the incoming email data to be analyzed.
    """
    message_id: Optional[str] = Field(None, max_length=255)
    sender_email: str = Field(..., max_length=255)
    recipient_email: str = Field(..., max_length=255)
    subject: str = Field("", max_length=1000)
    body_text: str = Field("", max_length=100000)
    body_html: Optional[str] = Field(None, max_length=100000)
    headers: Optional[List[EmailHeader]] = None
    raw_source: Optional[str] = Field(None, description="Raw EML content if available", max_length=200000)
    timestamp: Optional[str] = Field(None, max_length=100)

    @field_validator("sender_email", "recipient_email", mode="before")
    @classmethod
    def _normalize_address(cls, v):
        return normalize_email_address(v)

    @field_validator("sender_email", "recipient_email", mode="after")
    @classmethod
    def _validate_address_shape(cls, v):
        if not _LOOSE_EMAIL_RE.match(v):
            raise ValueError(f"'{v}' does not look like a valid email address")
        return v

class ThreatSignal(BaseModel):
    title: str
    detail: str
    points: float

class ThreatAnalysisResponse(BaseModel):
    """
    Model representing the result of the threat analysis.
    """
    message_id: str
    sender_email: Optional[str] = Field(None, description="Sender of the analyzed email")
    recipient_email: Optional[str] = Field(None, description="Recipient of the analyzed email")
    subject: Optional[str] = Field(None, description="Subject of the analyzed email")
    sender_ip: Optional[str] = Field(None, description="Sender IP extracted from the email's Received headers, if present")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0 to 100")
    threat_level: str = Field(..., description="e.g., 'Safe', 'Suspicious', 'Malicious'")
    detected_threats: List[ThreatSignal] = Field(default_factory=list)
    geolocation_info: Optional[dict] = None
    is_impossible_travel: bool = False
    travel_distance_km: Optional[float] = Field(None, description="Distance between the current and last known sender location, when impossible travel is evaluated")
    travel_speed_kmh: Optional[float] = Field(None, description="Implied travel speed between the two sender locations")
    evidence_hash: Optional[str] = Field(None, description="SHA-256 tamper-evident hash")
    previous_hash: Optional[str] = Field(None, description="Previous chain hash")
    chain_hash: Optional[str] = Field(None, description="Cryptographic chain hash")
    sequence: Optional[int] = Field(None, description="Position in the chain")
    components: Optional[dict] = Field(None, description="Breakdown of component scores")
    report_url: Optional[str] = Field(None, description="API endpoint to download the PDF report")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp of analysis")
