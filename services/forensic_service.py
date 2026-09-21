import hashlib
import json
import os
import logging
from datetime import datetime
from fpdf import FPDF
from models.email import EmailData, ThreatAnalysisResponse
from database import get_forensic_logs_collection

logger = logging.getLogger(__name__)

REPORT_DIR = "reports"

os.makedirs(REPORT_DIR, exist_ok=True)

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
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Consistent serialization for hashing
        serialized_data = json.dumps(data_to_hash, sort_keys=True).encode('utf-8')
        evidence_hash = hashlib.sha256(serialized_data).hexdigest()
        
        return evidence_hash, data_to_hash

    async def log_evidence(self, email: EmailData, analysis: ThreatAnalysisResponse) -> str:
        """
        Asynchronously logs the hash and metadata into the MongoDB tamper-evident vault.
        Returns the cryptographic hash.
        """
        evidence_hash, metadata = self.hash_evidence(email, analysis)
        
        log_entry = {
            "evidence_hash": evidence_hash,
            "metadata": metadata,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Asynchronously insert into the MongoDB collection
        try:
            collection = get_forensic_logs_collection()
            await collection.insert_one(log_entry)
            logger.info(f"Evidence logged successfully to MongoDB for message {email.message_id}. Hash: {evidence_hash}")
        except Exception as e:
            logger.error(f"Failed to write to MongoDB evidence vault: {e}")
            
        return evidence_hash

    def generate_pdf_report(self, email: EmailData, analysis: ThreatAnalysisResponse, evidence_hash: str) -> str:
        """
        Generates a PDF forensic report ready for CERT-In or SOC submission.
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        
        # Title
        pdf.set_font("Helvetica", style="B", size=18)
        pdf.cell(0, 10, txt="SOC Forensic Email Intelligence Report", ln=True, align="C")
        pdf.ln(5)
        
        # Executive Summary
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102) # Dark blue
        pdf.cell(0, 10, txt="Executive Summary", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        pdf.cell(0, 8, txt=f"Message ID: {analysis.message_id}", ln=True)
        
        # Color code threat level
        if analysis.threat_level == "Malicious":
            pdf.set_text_color(200, 0, 0) # Red
        elif analysis.threat_level == "Suspicious":
            pdf.set_text_color(200, 100, 0) # Orange
        else:
            pdf.set_text_color(0, 150, 0) # Green
            
        pdf.cell(0, 8, txt=f"Threat Level: {analysis.threat_level}", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, txt=f"Risk Score: {analysis.risk_score} / 100", ln=True)
        pdf.ln(5)
        
        # Email Metadata
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, txt="Email Artifacts", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        pdf.cell(0, 8, txt=f"From: {email.sender_email}", ln=True)
        pdf.cell(0, 8, txt=f"To: {email.recipient_email}", ln=True)
        
        # Handle long subjects
        subject = email.subject if email.subject else "No Subject"
        pdf.multi_cell(0, 8, txt=f"Subject: {subject}")
        pdf.ln(5)
        
        # Threats & Intelligence
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, txt="Detected Threats & Geo-Intelligence", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=12)
        
        if analysis.detected_threats:
            for threat in analysis.detected_threats:
                pdf.cell(0, 8, txt=f"- {threat}", ln=True)
        else:
            pdf.cell(0, 8, txt="No specific threats detected.", ln=True)
            
        if analysis.geolocation_info:
            loc = analysis.geolocation_info
            pdf.cell(0, 8, txt=f"Sender IP: {loc.get('ip', 'Unknown')} ({loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')})", ln=True)
            if analysis.is_impossible_travel:
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, txt="ALERT: IMPOSSIBLE TRAVEL DETECTED", ln=True)
                pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # Chain of Custody
        pdf.set_font("Helvetica", style="B", size=14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, txt="Chain of Custody (Tamper-Evident Ledger)", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=10)
        
        pdf.multi_cell(0, 6, txt="This report is accompanied by a cryptographic hash of the raw email artifacts to ensure tamper evidence. It has been recorded in the platform's immutable vault.")
        pdf.ln(2)
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 6, txt=f"SHA-256 Evidence Hash:\n{evidence_hash}")
        
        filename = os.path.join(REPORT_DIR, f"forensic_report_{analysis.message_id}.pdf")
        pdf.output(filename)
        return filename

forensic_service = ForensicService()
