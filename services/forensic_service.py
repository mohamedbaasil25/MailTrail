import hashlib
import json
import os
import re
import logging
from datetime import datetime, timezone
from fpdf import FPDF
from models.email import EmailData, ThreatAnalysisResponse
from database import get_forensic_logs_collection

logger = logging.getLogger(__name__)

REPORT_DIR = "reports"

os.makedirs(REPORT_DIR, exist_ok=True)

# message_id ultimately comes from an email's Message-ID header (or a
# client-supplied value) and is concatenated straight into a filesystem
# path both here and in the /report/{message_id} download route. A literal
# ".." *component* can't slip through today because it's always embedded
# inside the "forensic_report_..." prefix, but relying on that is fragile -
# sanitizing at the source means a future refactor of either call site
# can't reintroduce a path-traversal footgun.
_UNSAFE_ID_CHARS_RE = re.compile(r'[^A-Za-z0-9_.-]')

def safe_report_filename(message_id: str) -> str:
    safe_id = _UNSAFE_ID_CHARS_RE.sub("_", message_id or "unknown")[:200]
    return f"forensic_report_{safe_id}.pdf"

class ForensicService:
    def hash_evidence(self, email: EmailData, analysis: ThreatAnalysisResponse) -> tuple[str, dict]:
        """
        Creates a SHA-256 hash of the critical email artifacts and the analysis result.
        """
        data_to_hash = {
            "message_id": email.message_id,
            "sender": email.sender_email,
            "subject": email.subject,
            "body_snippet": email.body_text[:500] if email.body_text else "",
            "risk_score": analysis.risk_score,
            "threat_level": analysis.threat_level,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Consistent serialization for hashing
        serialized_data = json.dumps(data_to_hash, sort_keys=True).encode('utf-8')
        evidence_hash = hashlib.sha256(serialized_data).hexdigest()
        
        return evidence_hash, data_to_hash

    async def log_evidence(self, email: EmailData, analysis: ThreatAnalysisResponse) -> dict:
        """
        Asynchronously logs the hash and metadata into the MongoDB tamper-evident vault.
        Returns a dict containing evidence_hash, previous_hash, chain_hash, and sequence.
        """
        evidence_hash, metadata = self.hash_evidence(email, analysis)
        
        from database import get_last_forensic_record
        last_record = await get_last_forensic_record()
        
        sequence = 1
        previous_hash = "GENESIS_HASH_0000000000000000000000000000000000000000000000000000"
        
        if last_record:
            sequence = last_record.get("sequence", 0) + 1
            previous_hash = last_record.get("chain_hash", previous_hash)
            
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Calculate the cryptographic chain hash
        chain_data = f"{previous_hash}|{evidence_hash}|{sequence}|{timestamp}"
        chain_hash = hashlib.sha256(chain_data.encode('utf-8')).hexdigest()
        
        log_entry = {
            "sequence": sequence,
            "message_id": email.message_id,
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash,
            "chain_hash": chain_hash,
            "metadata": metadata,
            "created_at": timestamp
        }
        
        # Asynchronously insert into the MongoDB collection
        try:
            from database import get_forensic_logs_collection
            collection = get_forensic_logs_collection()
            await collection.insert_one(log_entry)
            logger.info(f"Evidence logged successfully to MongoDB for message {email.message_id}. Chain Hash: {chain_hash}")
        except Exception as e:
            logger.error(f"Failed to write to MongoDB evidence vault: {e}")
            
        return {
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash,
            "chain_hash": chain_hash,
            "sequence": sequence
        }

    def generate_pdf_report(self, email: EmailData, analysis: ThreatAnalysisResponse, evidence_hash: str) -> str:
        """
        Generates a PDF forensic report ready for CERT-In or SOC submission.
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        
        # Title
        pdf.set_font("Helvetica", style="B", size=18)
        pdf.cell(0, 10, text="SOC Forensic Email Intelligence Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)
        
        # Executive Summary
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102) # Dark blue
        pdf.cell(0, 10, text="Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        pdf.cell(0, 8, text=f"Message ID: {analysis.message_id}", new_x="LMARGIN", new_y="NEXT")
        
        # Color code threat level
        if analysis.threat_level == "Malicious":
            pdf.set_text_color(200, 0, 0) # Red
        elif analysis.threat_level == "Suspicious":
            pdf.set_text_color(200, 100, 0) # Orange
        else:
            pdf.set_text_color(0, 150, 0) # Green
            
        pdf.cell(0, 8, text=f"Threat Level: {analysis.threat_level}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, text=f"Risk Score: {analysis.risk_score} / 100", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Email Metadata
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, text="Email Artifacts", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        pdf.cell(0, 8, text=f"From: {email.sender_email}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, text=f"To: {email.recipient_email}", new_x="LMARGIN", new_y="NEXT")
        
        # Handle long subjects
        subject = email.subject if email.subject else "No Subject"
        pdf.multi_cell(0, 8, text=f"Subject: {subject}")
        pdf.ln(5)
        
        # Threats & Intelligence
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, text="Detected Threats & Geo-Intelligence", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        
        if analysis.detected_threats:
            for threat in analysis.detected_threats:
                pdf.set_font("Helvetica", style="B", size=11)
                # multi_cell defaults to new_x=RIGHT, unlike cell()'s LMARGIN/NEXT used
                # elsewhere in this file - without an explicit LMARGIN/NEXT reset
                # here, the next multi_cell call starts near the right page edge
                # with ~0 width left and raises "Not enough horizontal space".
                pdf.multi_cell(0, 6, text=f"- {threat.title}  (+{threat.points:g} pts)", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", size=10)
                pdf.multi_cell(0, 6, text=f"    {threat.detail}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", size=12)
                pdf.ln(1)
        else:
            pdf.cell(0, 8, text="No specific threats detected.", new_x="LMARGIN", new_y="NEXT")
            
        if analysis.geolocation_info:
            loc = analysis.geolocation_info
            source_note = " (simulated - no GeoIP database installed or IP not in dataset)" if loc.get("source") == "simulated" else " (MaxMind GeoLite2)"
            pdf.multi_cell(0, 8, text=f"Sender IP: {loc.get('ip', 'Unknown')} ({loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}){source_note}", new_x="LMARGIN", new_y="NEXT")
            if analysis.is_impossible_travel:
                pdf.set_text_color(255, 0, 0)
                distance_note = f" (~{analysis.travel_distance_km:g} km, ~{analysis.travel_speed_kmh:g} km/h)" if analysis.travel_distance_km is not None else ""
                pdf.multi_cell(0, 8, text=f"ALERT: IMPOSSIBLE TRAVEL DETECTED{distance_note}")
                pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # Chain of Custody
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, text="Chain of Custody (Tamper-Evident Ledger)", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=10)
        
        pdf.multi_cell(0, 6, text="This report is accompanied by a cryptographic hash of the raw email artifacts to ensure tamper evidence. It has been recorded in the platform's immutable vault.")
        pdf.ln(2)
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 6, text=f"SHA-256 Evidence Hash:\n{evidence_hash}")
        
        filename = os.path.join(REPORT_DIR, safe_report_filename(analysis.message_id))
        pdf.output(filename)
        return filename

forensic_service = ForensicService()
