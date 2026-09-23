from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Request, BackgroundTasks, Depends
from fastapi.responses import FileResponse
from typing import List
from models.email import EmailData, ThreatAnalysisResponse, ThreatSignal
import uuid
import os
from datetime import datetime, timedelta
from services.nlp_analyzer import nlp_analyzer
from services.geoip_service import geoip_service
from services.forensic_service import forensic_service
from services.heuristic_engine import score_heuristics
from services.dns_validator import validate_domain_auth
from services.threat_intel_service import threat_intel_service
from database import get_threat_intelligence_collection, Database
from api.auth import get_current_user, get_admin_user
from services.pii_redactor import redact_pii
from services.audit_service import log_audit_action
from jose import JWTError, jwt
from config import settings
from rate_limiter import limiter

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, token: str):
        # Validate JWT token
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            if not payload.get("sub"):
                await websocket.close(code=1008)
                return False
        except JWTError:
            await websocket.close(code=1008)
            return False
            
        await websocket.accept()
        self.active_connections.append(websocket)
        return True

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

@router.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=1008)
        return
    is_connected = await manager.connect(websocket, token)
    if not is_connected:
        return
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@router.post("/analyze", response_model=ThreatAnalysisResponse, summary="Analyze an email for threats")
@limiter.limit("10/minute")
async def analyze_email(request: Request, email: EmailData, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    """
    Endpoint to ingest and parse an email, perform multi-signal detection, 
    and return a risk score and threat intelligence.
    """
    if not email.sender_email or not email.recipient_email:
        raise HTTPException(status_code=400, detail="Sender and recipient emails are required.")
    
    await log_audit_action(user["username"], "ANALYZE_EMAIL", f"Sender: {email.sender_email}, Subject: {email.subject}")
    
    analysis_response, evidence_hash = await run_analysis(email, user["username"])
    
    # Offload PDF generation to background to prevent event loop blocking
    background_tasks.add_task(forensic_service.generate_pdf_report, email, analysis_response, evidence_hash)
    
    return analysis_response

async def run_analysis(email: EmailData, username: str = "system") -> tuple:
    """
    Core analysis pipeline — callable from both HTTP routes and IMAP worker.
    Returns (ThreatAnalysisResponse, evidence_hash).
    """
    # Apply Data Privacy (PII Redaction)
    email.body_text = redact_pii(email.body_text)
    email.subject = redact_pii(email.subject)

    detected_threats = []
    
    # 1. NLP Phishing Intent Analysis
    text_to_analyze = f"{email.subject} {email.body_text}"
    nlp_result = nlp_analyzer.analyze_text(text_to_analyze)
    nlp_risk_score = nlp_result["phishing_probability"] * 100
    
    if nlp_risk_score >= 70:
        detected_threats.append(ThreatSignal(title="NLP Analysis (Phishing)", detail=f"High phishing intent detected (Label: {nlp_result['intent_label']})", points=round(nlp_risk_score * 0.5, 1)))
    elif nlp_risk_score >= 40:
        detected_threats.append(ThreatSignal(title="NLP Analysis (Suspicious)", detail=f"Suspicious language detected (Label: {nlp_result['intent_label']})", points=round(nlp_risk_score * 0.5, 1)))

    auth_risk_score = 0.0
    domain = email.sender_email.split("@")[-1] if email.sender_email else None
    
    # Active DNS Lookups for SPF & DMARC
    auth_results = validate_domain_auth(domain)
    
    if not auth_results.get("spf_valid"):
        detected_threats.append(ThreatSignal(title="SPF Missing/Invalid", detail=f"Domain {domain} lacks valid SPF records.", points=30.0))
        auth_risk_score += 30.0

    if not auth_results.get("dmarc_valid"):
        detected_threats.append(ThreatSignal(title="DMARC Missing/Invalid", detail=f"Domain {domain} lacks valid DMARC records.", points=40.0))
        auth_risk_score += 40.0
            
    # 2. GeoIP and Impossible Travel Detection
    geoip_risk_score = 0.0 
    geolocation_info = None
    is_impossible_travel = False
    
    sender_ip = geoip_service.extract_sender_ip(email.headers)
    if sender_ip:
        geolocation_info = geoip_service.lookup_ip(sender_ip)
        if geolocation_info:
            geolocation_info["timestamp"] = datetime.utcnow()
            mock_last_login = {
                "lat": 19.0760,
                "lon": 72.8777,
                "timestamp": datetime.utcnow() - timedelta(hours=1)
            }
            is_impossible, speed = geoip_service.check_impossible_travel(geolocation_info, mock_last_login)
            if is_impossible:
                is_impossible_travel = True
                detected_threats.append(ThreatSignal(title="Impossible Travel", detail=f"Flagged! Calculated speed: {int(speed)} km/h.", points=20.0))
                geoip_risk_score = 100.0
    
    # 3. Ensemble Risk Score Calculation
    heuristic_results = score_heuristics(text_to_analyze)
    for sig in heuristic_results["signals"]:
        detected_threats.append(ThreatSignal(title=sig["title"], detail=sig["detail"], points=sig["points"]))
        
    # 4. External Threat Intelligence Integration
    intel_signals = threat_intel_service.check_indicators(text_to_analyze)
    intel_risk_score = 0.0
    for sig in intel_signals:
        detected_threats.append(ThreatSignal(title=sig["title"], detail=sig["detail"], points=sig["points"]))
        intel_risk_score += sig["points"]
        
    w_nlp, w_heu, w_auth, w_geoip, w_intel = 0.25, 0.25, 0.2, 0.15, 0.15
    final_risk_score = (nlp_risk_score * w_nlp) + (heuristic_results["score"] * w_heu) + (auth_risk_score * w_auth) + (geoip_risk_score * w_geoip) + (min(intel_risk_score, 100.0) * w_intel)
    final_risk_score = min(final_risk_score, 100.0)
    
    if final_risk_score >= 75:
        threat_level = "Malicious"
    elif final_risk_score >= 40:
        threat_level = "Suspicious"
    else:
        threat_level = "Safe"

    analysis_response = ThreatAnalysisResponse(
        message_id=email.message_id or str(uuid.uuid4()),
        sender_email=email.sender_email,
        subject=email.subject,
        risk_score=round(final_risk_score, 2),
        threat_level=threat_level,
        detected_threats=detected_threats,
        geolocation_info=geolocation_info,
        is_impossible_travel=is_impossible_travel
    )
    
    # 5. Tamper-Evident Forensic Logging & PDF Generation
    evidence_hash = await forensic_service.log_evidence(email, analysis_response)
    analysis_response.evidence_hash = evidence_hash
    analysis_response.report_url = f"/api/v1/report/{analysis_response.message_id}"
    
    # Persist the full analysis to MongoDB threat intelligence
    collection = get_threat_intelligence_collection()
    document = analysis_response.model_dump()
    await collection.insert_one(document)
    
    # Notify websockets
    await manager.broadcast(analysis_response.model_dump())
    
    return analysis_response, evidence_hash

@router.get("/emails", response_model=list[ThreatAnalysisResponse], summary="Get all analyzed emails")
async def get_emails(user=Depends(get_current_user)):
    """
    Returns the list of all analyzed emails from MongoDB for the dashboard.
    """
    collection = get_threat_intelligence_collection()
    # Sort descending by timestamp to get newest first
    cursor = collection.find().sort("timestamp", -1)
    
    emails = []
    async for document in cursor:
        if "_id" in document:
            del document["_id"] # Pydantic model doesn't expect the Mongo _id
        emails.append(ThreatAnalysisResponse(**document))
        
    return emails

@router.get("/vault/search", response_model=list[ThreatAnalysisResponse], summary="Search Evidence Vault")
async def search_vault(query: str, limit: int = 50, user=Depends(get_current_user)):
    """
    Search the threat intelligence vault using text search on subject, sender, and body.
    """
    await log_audit_action(user["username"], "SEARCH_VAULT", f"Query: {query}")
    collection = get_threat_intelligence_collection()
    
    if not query:
        cursor = collection.find().sort("timestamp", -1).limit(limit)
    else:
        cursor = collection.find(
            {"$text": {"$search": query}},
            {"score": {"$meta": "textScore"}}
        ).sort([("score", {"$meta": "textScore"}), ("timestamp", -1)]).limit(limit)
        
    emails = []
    async for document in cursor:
        if "_id" in document:
            del document["_id"]
        if "score" in document:
            del document["score"]
        emails.append(ThreatAnalysisResponse(**document))
        
    return emails

@router.delete("/investigations", summary="Clear Vault")
async def clear_vault(user=Depends(get_admin_user)):
    """
    Clears all evidence from the vault (Requires Admin)
    """
    await log_audit_action(user["username"], "CLEAR_VAULT", "Admin cleared all investigations")
    collection = get_threat_intelligence_collection()
    await collection.delete_many({})
    return {"message": "Vault cleared"}

@router.get("/report/{message_id}", summary="Download Forensic PDF Report")
async def download_report(message_id: str, user=Depends(get_current_user)):
    """
    Downloads the generated forensic PDF report for a given message ID.
    """
    file_path = os.path.join("reports", f"forensic_report_{message_id}.pdf")
    if os.path.exists(file_path):
        return FileResponse(path=file_path, filename=f"SOC_Report_{message_id}.pdf", media_type="application/pdf")
    raise HTTPException(status_code=404, detail="Forensic report not found")

@router.get("/health", summary="Health Check")
async def health_check():
    """
    Simple health check endpoint to verify the API is running.
    """
    return {"status": "healthy", "ok": True, "service": "Email Intelligence API"}
