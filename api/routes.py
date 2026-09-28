from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Request, BackgroundTasks, Depends
from fastapi.responses import FileResponse
from typing import List
from models.email import EmailData, ThreatAnalysisResponse, ThreatSignal
import asyncio
import logging
import uuid
import os
from datetime import datetime, timedelta, timezone
from services.nlp_analyzer import nlp_analyzer
from services.geoip_service import geoip_service
from services.forensic_service import forensic_service
from services.heuristic_engine import score_heuristics
from services.dns_validator import validate_domain_auth_async
from services.threat_intel_service import threat_intel_service
from database import get_threat_intelligence_collection, Database
from api.auth import get_current_user, get_admin_user
from services.pii_redactor import redact_pii
from services.audit_service import log_audit_action
from jwt import PyJWTError
import jwt
from config import settings
from rate_limiter import limiter
import json
import redis.asyncio as redis_async

router = APIRouter()
logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.redis = None
        self.pubsub = None

    async def connect_redis(self):
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            logger.info("REDIS_URL not set, falling back to in-memory WebSockets.")
            return
        try:
            self.redis = redis_async.from_url(redis_url)
            self.pubsub = self.redis.pubsub()
            await self.pubsub.subscribe("updates")
            asyncio.create_task(self._listen())
            logger.info(f"Connected to Redis for WebSockets at {redis_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis for WebSockets: {e}")

    async def _listen(self):
        try:
            async for message in self.pubsub.listen():
                if message["type"] == "message":
                    data = message["data"].decode("utf-8")
                    for connection in self.active_connections:
                        try:
                            await connection.send_text(data)
                        except Exception as exc:
                            logger.debug(f"WebSocket broadcast failed: {exc}")
        except Exception as e:
            logger.error(f"Redis pub/sub listen error: {e}")

    async def connect(self, websocket: WebSocket, token: str):
        # Validate JWT token
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            if not payload.get("sub"):
                await websocket.close(code=1008)
                return False
        except PyJWTError:
            await websocket.close(code=1008)
            return False
            
        await websocket.accept()
        self.active_connections.append(websocket)
        return True

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        if getattr(self, 'redis', None):
            await self.redis.publish("updates", json.dumps(message))
        else:
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as exc:
                    logger.debug(f"WebSocket broadcast failed: {exc}")

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
    detected_threats = []
    
    # 1. NLP Phishing Intent Analysis
    text_to_analyze = f"{email.subject} {email.body_text}"
    # analyze_text() runs a synchronous transformers pipeline (model load +
    # CPU inference) that can take real wall-clock time; calling it directly
    # here would block the whole asyncio event loop for every concurrent
    # request. Offload it to a worker thread instead.
    nlp_result = await asyncio.to_thread(nlp_analyzer.analyze_text, text_to_analyze)
    nlp_risk_score = 0.0
    nlp_available = nlp_result.get("status") == "available"
    
    if nlp_available:
        nlp_risk_score = nlp_result["phishing_probability"] * 100
        if nlp_risk_score >= 70:
            detected_threats.append(ThreatSignal(title="NLP Analysis (Phishing)", detail=f"High phishing intent detected (Label: {nlp_result['intent_label']})", points=round(nlp_risk_score * 0.5, 1)))
        elif nlp_risk_score >= 40:
            detected_threats.append(ThreatSignal(title="NLP Analysis (Suspicious)", detail=f"Suspicious language detected (Label: {nlp_result['intent_label']})", points=round(nlp_risk_score * 0.5, 1)))
    else:
        detected_threats.append(ThreatSignal(title="NLP Analysis", detail="NLP scoring is currently UNAVAILABLE.", points=0.0))

    auth_risk_score = 0.0
    domain = email.sender_email.split("@")[-1] if email.sender_email else None
    
    # Active DNS Lookups for SPF & DMARC
    auth_results = await validate_domain_auth_async(domain)
    
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
    travel_distance_km = None
    travel_speed_kmh = None
    
    sender_ip = geoip_service.extract_sender_ip(email.headers)
    if sender_ip:
        geolocation_info = await asyncio.to_thread(geoip_service.lookup_ip, sender_ip)
        if geolocation_info:
            geolocation_info["timestamp"] = datetime.now(timezone.utc).isoformat()
            
            # Fetch real last location for this sender
            collection = get_threat_intelligence_collection()
            last_record = await collection.find_one(
                {
                    "sender_email": email.sender_email, 
                    "geolocation_info": {"$ne": None}
                },
                sort=[("timestamp", -1)]
            )
            
            if last_record and last_record.get("geolocation_info"):
                last_location = last_record["geolocation_info"]
                is_impossible, speed, distance = geoip_service.check_impossible_travel(geolocation_info, last_location)
                travel_speed_kmh = round(speed, 1)
                travel_distance_km = round(distance, 1)
                if is_impossible:
                    is_impossible_travel = True
                    detected_threats.append(ThreatSignal(title="Impossible Travel", detail=f"Flagged! ~{int(distance)} km in the observed window implies a speed of {int(speed)} km/h.", points=20.0))
                    geoip_risk_score = 100.0
    
    # 3. Ensemble Risk Score Calculation
    heuristic_results = score_heuristics(text_to_analyze, sender_domain=domain)
    for sig in heuristic_results["signals"]:
        detected_threats.append(ThreatSignal(title=sig["title"], detail=sig["detail"], points=sig["points"]))
        
    # 4. External Threat Intelligence Integration
    # Runs synchronous HTTP calls (with retry/backoff) under the hood, so it
    # must go through a thread - calling it directly here would block the
    # event loop for every concurrent /analyze request while it retries.
    intel_response = await asyncio.to_thread(threat_intel_service.check_indicators, text_to_analyze)
    intel_risk_score = 0.0
    intel_status = intel_response.get("status")
    intel_available = intel_status == "available"
    
    if intel_available:
        for sig in intel_response.get("signals", []):
            detected_threats.append(ThreatSignal(title=sig["title"], detail=sig["detail"], points=sig["points"]))
            intel_risk_score += sig["points"]
    elif intel_status == "degraded":
        detected_threats.append(ThreatSignal(title="Threat Intel", detail="External threat intelligence provider is configured but unreachable right now; indicators could not be checked.", points=0.0))
    else:
        detected_threats.append(ThreatSignal(title="Threat Intel", detail="External threat intelligence is UNAVAILABLE.", points=0.0))
        
    # Dynamic Weighting
    base_weights = {"nlp": 0.25, "heu": 0.25, "auth": 0.20, "geo": 0.15, "intel": 0.15}
    active_weights = {
        "nlp": base_weights["nlp"] if nlp_available else 0.0,
        "heu": base_weights["heu"],
        "auth": base_weights["auth"],
        "geo": base_weights["geo"],
        "intel": base_weights["intel"] if intel_available else 0.0
    }
    
    total_active_weight = sum(active_weights.values())
    if total_active_weight == 0:
        total_active_weight = 1.0 # Fallback safety
        
    # Normalize weights
    w_nlp = active_weights["nlp"] / total_active_weight
    w_heu = active_weights["heu"] / total_active_weight
    w_auth = active_weights["auth"] / total_active_weight
    w_geo = active_weights["geo"] / total_active_weight
    w_intel = active_weights["intel"] / total_active_weight
    
    final_risk_score = (nlp_risk_score * w_nlp) + (heuristic_results["score"] * w_heu) + (auth_risk_score * w_auth) + (geoip_risk_score * w_geo) + (min(intel_risk_score, 100.0) * w_intel)
    final_risk_score = min(final_risk_score, 100.0)
    
    if final_risk_score >= 75:
        threat_level = "Malicious"
    elif final_risk_score >= 40:
        threat_level = "Suspicious"
    else:
        threat_level = "Safe"

    analysis_response = ThreatAnalysisResponse(
        message_id=email.message_id or str(uuid.uuid4()),
        # NOTE: sender/recipient are NOT run through redact_pii() here.
        # redact_pii() is built to scrub PII *embedded in free text* (a body
        # or subject that happens to mention an email/SSN/phone/IP/URL) - but
        # sender_email and recipient_email ARE, by definition, always an
        # email address, so redact_pii's own email-masking rule matched the
        # entire field every single time and replaced it outright with the
        # literal string "[REDACTED_EMAIL]". That silently destroyed the one
        # piece of data this whole tool exists to capture - the vault, the
        # search index, and the PDF report were all showing that placeholder
        # instead of the real sender on every record.
        sender_email=email.sender_email,
        recipient_email=email.recipient_email,
        subject=redact_pii(email.subject),
        sender_ip=sender_ip,
        risk_score=round(final_risk_score, 2),
        threat_level=threat_level,
        detected_threats=detected_threats,
        geolocation_info=geolocation_info,
        is_impossible_travel=is_impossible_travel,
        travel_distance_km=travel_distance_km,
        travel_speed_kmh=travel_speed_kmh,
        components={
            "nlp": round(nlp_risk_score, 2),
            "heuristics": round(heuristic_results["score"], 2),
            "dns": round(auth_risk_score, 2),
            "geo": round(geoip_risk_score, 2),
            "threat_intel": round(intel_risk_score, 2)
        }
    )
    
    # 5. Tamper-Evident Forensic Logging & PDF Generation
    chain_info = await forensic_service.log_evidence(email, analysis_response)
    analysis_response.evidence_hash = chain_info["evidence_hash"]
    analysis_response.previous_hash = chain_info["previous_hash"]
    analysis_response.chain_hash = chain_info["chain_hash"]
    analysis_response.sequence = chain_info["sequence"]
    
    analysis_response.report_url = f"/api/v1/report/{analysis_response.message_id}"
    
    # Persist the full analysis to MongoDB threat intelligence
    collection = get_threat_intelligence_collection()
    document = analysis_response.model_dump()
    await collection.insert_one(document)
    
    # Notify websockets
    await manager.broadcast(analysis_response.model_dump())
    
    return analysis_response, chain_info["evidence_hash"]

@router.get("/verify-chain", summary="Verify the Forensic Evidence Hash Chain")
async def verify_chain(user=Depends(get_current_user)):
    """
    Retrieves the entire evidence ledger from MongoDB and mathematically 
    recalculates each block's cryptographic hash to verify chain integrity.
    """
    from database import get_all_forensic_records
    import hashlib
    
    records = await get_all_forensic_records()
    if not records:
        return {"valid": True, "checked_records": 0, "broken_at": None, "message": "Chain is empty"}
        
    expected_previous = "GENESIS_HASH_0000000000000000000000000000000000000000000000000000"
    
    for i, record in enumerate(records):
        sequence = record.get("sequence")
        evidence_hash = record.get("evidence_hash")
        previous_hash = record.get("previous_hash")
        chain_hash = record.get("chain_hash")
        timestamp = record.get("created_at")
        
        # Check chain continuity
        if previous_hash != expected_previous:
            return {
                "valid": False,
                "checked_records": i,
                "broken_at": sequence,
                "reason": "previous_hash_mismatch",
                "message": f"Block {sequence} previous_hash does not match expected."
            }
            
        # Check block integrity
        chain_data = f"{previous_hash}|{evidence_hash}|{sequence}|{timestamp}"
        recalculated = hashlib.sha256(chain_data.encode('utf-8')).hexdigest()
        
        if recalculated != chain_hash:
            return {
                "valid": False,
                "checked_records": i,
                "broken_at": sequence,
                "reason": "chain_hash_mismatch",
                "message": f"Block {sequence} cryptographic hash is invalid/tampered."
            }
            
        expected_previous = chain_hash
        
    return {
        "valid": True,
        "checked_records": len(records),
        "broken_at": None,
        "message": "The evidence chain is cryptographically verified."
    }

@router.get("/emails", response_model=list[ThreatAnalysisResponse], summary="Get all analyzed emails")
@limiter.limit("30/minute")
async def get_emails(request: Request, user=Depends(get_current_user)):
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
@limiter.limit("30/minute")
async def search_vault(request: Request, query: str, limit: int = 50, user=Depends(get_current_user)):
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

from pydantic import BaseModel

class DeleteRequest(BaseModel):
    reason: str

@router.delete("/investigations", summary="Clear Vault")
@limiter.limit("3/minute")
async def clear_vault(request: Request, body: DeleteRequest, user=Depends(get_admin_user)):
    """
    Clears all evidence from the vault (Requires Admin and explicit reason)
    """
    if not body.reason or len(body.reason) < 10:
        raise HTTPException(status_code=400, detail="A valid reason of at least 10 characters is required.")
        
    await log_audit_action(user["username"], "CLEAR_VAULT", f"Admin cleared all investigations. Reason: {body.reason}")
    
    collection = get_threat_intelligence_collection()
    await collection.delete_many({})
    
    # Also delete forensic logs
    from database import get_forensic_logs_collection
    forensic_coll = get_forensic_logs_collection()
    await forensic_coll.delete_many({})
    
    return {"message": "Vault cleared"}

@router.get("/report/{message_id}", summary="Download Forensic PDF Report")
async def download_report(message_id: str, user=Depends(get_current_user)):
    """
    Downloads the generated forensic PDF report for a given message ID.
    """
    from services.forensic_service import safe_report_filename
    file_path = os.path.join("reports", safe_report_filename(message_id))
    if os.path.exists(file_path):
        return FileResponse(path=file_path, filename=f"SOC_Report_{message_id}.pdf", media_type="application/pdf")
    raise HTTPException(status_code=404, detail="Forensic report not found")

@router.get("/health", summary="Readiness Check")
async def health_check():
    """
    Readiness probe: is the API not just running, but actually able to
    serve real traffic? Pings MongoDB - if that fails, callers get a 503
    instead of a false "healthy", so a load balancer/orchestrator knows to
    stop routing traffic here (and, in a multi-instance deployment, route
    it to an instance whose DB connection is actually fine) instead of
    silently serving broken requests. The old version of this endpoint
    returned a hardcoded 200 unconditionally, regardless of whether Mongo
    was reachable at all.
    """
    try:
        db = Database.get_db()
        await db.command("ping")
    except Exception as exc:
        logger.error(f"Readiness check failed - database unreachable: {exc}")
        raise HTTPException(status_code=503, detail="Database unreachable")
    return {"status": "healthy", "ok": True, "service": "Email Intelligence API", "database": "connected"}
