import datetime
import logging
from database import Database

logger = logging.getLogger(__name__)

async def log_audit_action(username: str, action: str, details: str = None):
    """
    Logs an analyst action to the audit_logs collection for internal SOC auditing.
    """
    try:
        if Database.db is None:
            logger.warning("Database not connected; cannot log audit action.")
            return

        audit_collection = Database.db["audit_logs"]
        
        log_entry = {
            "timestamp": datetime.datetime.utcnow(),
            "username": username,
            "action": action,
            "details": details or ""
        }
        
        await audit_collection.insert_one(log_entry)
        logger.info(f"AUDIT: {username} performed {action}")
    except Exception as e:
        logger.error(f"Failed to log audit action: {e}")
