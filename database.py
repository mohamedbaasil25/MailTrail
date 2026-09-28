import logging
import re
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

logger = logging.getLogger(__name__)

def _redact_mongo_uri(uri: str) -> str:
    """
    Strips any inline username:password credentials before a Mongo URI is
    ever written to a log, e.g. mongodb://user:pass@host/ -> mongodb://***@host/.
    Logging the raw URI would otherwise leak DB credentials into log files/
    aggregators anywhere this connection message is emitted.
    """
    return re.sub(r"//[^@/]+@", "//***@", uri)

class Database:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    async def connect_db(cls):
        """Initializes the database connection pool."""
        if cls.client is None:
            logger.info(f"Connecting to MongoDB at {_redact_mongo_uri(settings.mongo_uri)}...")
            cls.client = AsyncIOMotorClient(settings.mongo_uri)
            cls.db = cls.client[settings.mongo_db_name]
            
            # Initialize indexes
            import pymongo
            from pymongo.errors import OperationFailure
            await cls.db.threat_intelligence.create_index([("timestamp", pymongo.DESCENDING)])
            await cls.db.threat_intelligence.create_index([("message_id", pymongo.ASCENDING)])
            # MongoDB allows only one text index per collection, so if an
            # older version of this index (fewer fields) already exists,
            # drop it first - otherwise create_index() with a different
            # field list fails outright instead of updating it, and the
            # vault search silently keeps running against the stale index
            # (recipient_email/sender_ip wouldn't be searchable even though
            # the code below asks for them).
            desired_text_fields = {"subject", "sender_email", "recipient_email", "sender_ip"}
            try:
                existing_indexes = await cls.db.threat_intelligence.index_information()
                for name, spec in existing_indexes.items():
                    if any(v == "text" for _, v in spec.get("key", [])):
                        indexed_fields = {k for k, v in spec.get("weights", {}).items()} or {
                            k for k, v in spec.get("key", []) if v == "text"
                        }
                        if indexed_fields != desired_text_fields:
                            logger.info(f"Dropping outdated text index '{name}' ({indexed_fields}) to rebuild with {desired_text_fields}")
                            await cls.db.threat_intelligence.drop_index(name)
                await cls.db.threat_intelligence.create_index([
                    ("subject", pymongo.TEXT),
                    ("sender_email", pymongo.TEXT),
                    ("recipient_email", pymongo.TEXT),
                    ("sender_ip", pymongo.TEXT),
                ])
            except OperationFailure as e:
                logger.error(f"Could not (re)build vault text index: {e}")
            
            # Forensic Logs indexes
            await cls.db.forensic_logs.create_index([("sequence", pymongo.ASCENDING)], unique=True)
            await cls.db.forensic_logs.create_index([("message_id", pymongo.ASCENDING)])
            
            # Create a TTL index for audit logs (90 days = 7776000 seconds)
            await cls.db.audit_logs.create_index("timestamp", expireAfterSeconds=7776000)
            
            logger.info("MongoDB indexes verified.")

    @classmethod
    async def close_db(cls):
        """Closes the database connection pool."""
        if cls.client is not None:
            cls.client.close()
            logger.info("MongoDB connection closed.")

    @classmethod
    def get_db(cls):
        return cls.db

def get_forensic_logs_collection():
    return Database.get_db().get_collection("forensic_logs")

def get_threat_intelligence_collection():
    return Database.get_db().get_collection("threat_intelligence")

async def get_last_forensic_record():
    collection = get_forensic_logs_collection()
    cursor = collection.find().sort("sequence", -1).limit(1)
    async for doc in cursor:
        return doc
    return None

async def get_all_forensic_records():
    collection = get_forensic_logs_collection()
    cursor = collection.find().sort("sequence", 1)
    return [doc async for doc in cursor]
