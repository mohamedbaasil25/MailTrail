from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

class EmailHeader(BaseModel):
    name: str
    value: str

class EmailData(BaseModel):
    """
    Model representing the incoming email data to be analyzed.
    """
    message_id: Optional[str] = Field(None, max_length=255)
    sender_email: EmailStr = Field(..., max_length=255)
    recipient_email: EmailStr = Field(..., max_length=255)
    subject: str = Field("", max_length=1000)
    body_text: str = Field("", max_length=100000)
    body_html: Optional[str] = Field(None, max_length=100000)
    headers: Optional[List[EmailHeader]] = None
    raw_source: Optional[str] = Field(None, description="Raw EML content if available", max_length=200000)
    timestamp: Optional[str] = Field(None, max_length=100)

class ThreatSignal(BaseModel):
    title: str
    detail: str
    points: float

class ThreatAnalysisResponse(BaseModel):
    """
    Model representing the result of the threat analysis.
    """
    message_id: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0 to 100")
    threat_level: str = Field(..., description="e.g., 'Safe', 'Suspicious', 'Malicious'")
    detected_threats: List[ThreatSignal] = Field(default_factory=list)
    geolocation_info: Optional[dict] = None
    is_impossible_travel: bool = False
    evidence_hash: Optional[str] = Field(None, description="SHA-256 tamper-evident hash")
    report_url: Optional[str] = Field(None, description="API endpoint to download the PDF report")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="ISO timestamp of analysis")
