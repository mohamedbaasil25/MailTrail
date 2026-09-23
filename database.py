import logging
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

logger = logging.getLogger(__name__)

class Database:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    async def connect_db(cls):
        """Initializes the database connection pool."""
        if cls.client is None:
            logger.info(f"Connecting to MongoDB at {settings.mongo_uri}...")
            cls.client = AsyncIOMotorClient(settings.mongo_uri)
            cls.db = cls.client[settings.mongo_db_name]
            
            # Initialize indexes
            import pymongo
            await cls.db.threat_intelligence.create_index([("timestamp", pymongo.DESCENDING)])
            await cls.db.threat_intelligence.create_index([("message_id", pymongo.ASCENDING)])
            await cls.db.threat_intelligence.create_index([("subject", pymongo.TEXT), ("sender_email", pymongo.TEXT)])
            
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
