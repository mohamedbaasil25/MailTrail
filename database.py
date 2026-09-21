import os
import logging
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

# Default connection string for local development
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("MONGO_DB_NAME", "email_intelligence_db")

class Database:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    async def connect_db(cls):
        """Initializes the database connection pool."""
        if cls.client is None:
            logger.info(f"Connecting to MongoDB at {MONGO_URI}...")
            cls.client = AsyncIOMotorClient(MONGO_URI)
            cls.db = cls.client[DB_NAME]
            
            # Initialize indexes
            import pymongo
            await cls.db.threat_intelligence.create_index([("timestamp", pymongo.DESCENDING)])
            await cls.db.threat_intelligence.create_index([("message_id", pymongo.ASCENDING)])
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
