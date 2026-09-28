import sys

def modify_routes():
    with open("api/routes.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    # 1. Imports
    if "import json" not in content:
        content = content.replace("from config import settings\nfrom rate_limiter import limiter", "from config import settings\nfrom rate_limiter import limiter\nimport json\nimport redis.asyncio as redis_async")
        if "from config import settings\r\nfrom rate_limiter import limiter" in content:
            content = content.replace("from config import settings\r\nfrom rate_limiter import limiter", "from config import settings\r\nfrom rate_limiter import limiter\r\nimport json\r\nimport redis.asyncio as redis_async")
            
    # 2. ConnectionManager __init__
    old_init = "    def __init__(self):\n        self.active_connections: List[WebSocket] = []"
    new_init = """    def __init__(self):
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
            logger.error(f"Redis pub/sub listen error: {e}")"""
    
    if "def __init__(self):\r\n" in content:
        old_init = old_init.replace("\n", "\r\n")
        new_init = new_init.replace("\n", "\r\n")
        
    content = content.replace(old_init, new_init)
    
    # 3. broadcast
    old_broadcast = """    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as exc:
                # A client that has already disconnected (tab closed,
                # network drop) is routine here, not exceptional - but
                # logging it at debug means a genuinely unexpected
                # serialization/transport bug doesn't vanish silently.
                logger.debug(f"WebSocket broadcast to a client failed (likely disconnected): {exc}")"""
    new_broadcast = """    async def broadcast(self, message: dict):
        if getattr(self, 'redis', None):
            await self.redis.publish("updates", json.dumps(message))
        else:
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as exc:
                    logger.debug(f"WebSocket broadcast failed: {exc}")"""

    if "    async def broadcast(self, message: dict):\r\n" in content:
        old_broadcast = old_broadcast.replace("\n", "\r\n")
        new_broadcast = new_broadcast.replace("\n", "\r\n")
        
    content = content.replace(old_broadcast, new_broadcast)
    
    with open("api/routes.py", "w", encoding="utf-8") as f:
        f.write(content)


def modify_main():
    with open("main.py", "r", encoding="utf-8") as f:
        content = f.read()

    # Change lifespan to call connect_redis
    old_lifespan = """    await Database.connect_db()
    asyncio.create_task(imap_worker())"""
    new_lifespan = """    await Database.connect_db()
    from api.routes import manager
    await manager.connect_redis()
    asyncio.create_task(imap_worker())"""
    
    if "await Database.connect_db()\r\n" in content:
        old_lifespan = old_lifespan.replace("\n", "\r\n")
        new_lifespan = new_lifespan.replace("\n", "\r\n")
        
    content = content.replace(old_lifespan, new_lifespan)
    
    # Update imap_worker to use aioimaplib (wait, we decided to use imapclient in a thread if we want robust IDLE, or just use imapclient IDLE loop in thread).
    # Since we are modifying main, let's just write the worker here.
    new_worker = """async def imap_worker():
    imap_server = os.getenv("IMAP_SERVER")
    username = os.getenv("IMAP_USER")
    password = os.getenv("IMAP_PASS")
    
    if not all([imap_server, username, password]):
        logging.info("IMAP credentials not set. Automated inbox scanning is disabled.")
        return
        
    logging.info("Starting automated IMAP scanning with IDLE support...")
    while True:
        try:
            from services.imap_client import fetch_unseen_emails_and_idle
            loop = asyncio.get_running_loop()
            
            # Since IDLE is blocking, run it in an executor.
            # We'll pass a callback to handle parsed emails
            def on_emails_fetched(emails):
                for email in emails:
                    try:
                        # Schedule coroutine from another thread
                        asyncio.run_coroutine_threadsafe(
                            run_analysis(email, username="imap_worker"), 
                            loop
                        )
                    except Exception as e:
                        logging.error(f"Error triggering analysis: {e}")
                        
            await loop.run_in_executor(None, fetch_unseen_emails_and_idle, imap_server, username, password, on_emails_fetched)
        except Exception as e:
            logging.error(f"IMAP Worker error: {e}")
            await asyncio.sleep(60)"""

    import re
    # We'll regex replace the whole imap_worker function
    content = re.sub(r'async def imap_worker\(\):.*?(?=@asynccontextmanager)', new_worker + "\n\n", content, flags=re.DOTALL)
    
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(content)

def modify_imap_client():
    with open("services/imap_client.py", "r", encoding="utf-8") as f:
        content = f.read()

    new_func = """
from imapclient import IMAPClient
import time

def parse_imapclient_message(msg_data: bytes) -> EmailData:
    msg = email.message_from_bytes(msg_data, policy=default)
    headers = [EmailHeader(name=k, value=str(v)) for k, v in msg.items()]
    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    message_id = msg.get("Message-ID", "")
    date_ = msg.get("Date", "")
    
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        decoded_payload = payload.decode(charset, errors="replace")
                        if content_type == "text/plain":
                            body_text += decoded_payload
                        elif content_type == "text/html":
                            body_html += decoded_payload
                except Exception as e:
                    logger.warning(f"Error decoding multipart: {e}")
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                decoded_payload = payload.decode(charset, errors="replace")
                if content_type == "text/plain":
                    body_text = decoded_payload
                elif content_type == "text/html":
                    body_html = decoded_payload
        except Exception as e:
            logger.warning(f"Error decoding payload: {e}")
            
    return EmailData(
        message_id=message_id,
        sender_email=extract_email_address(sender),
        recipient_email=extract_email_address(recipient),
        subject=subject,
        body_text=body_text.strip(),
        body_html=body_html.strip() if body_html else None,
        headers=headers,
        timestamp=date_
    )

def fetch_unseen_emails_and_idle(imap_server: str, username: str, password: str, callback):
    while True:
        try:
            with IMAPClient(imap_server) as server:
                server.login(username, password)
                server.select_folder("INBOX")
                
                # First fetch any UNSEEN
                messages = server.search("UNSEEN")
                if messages:
                    emails_data = []
                    fetch_data = server.fetch(messages, ["RFC822"])
                    for msg_id, data in fetch_data.items():
                        raw_email = data[b'RFC822']
                        emails_data.append(parse_imapclient_message(raw_email))
                    if emails_data:
                        callback(emails_data)
                
                # Now go into IDLE mode
                server.idle()
                logger.info("IMAP IDLE started.")
                
                while True:
                    responses = server.idle_check(timeout=30)
                    if responses:
                        # Something changed, exit IDLE
                        server.idle_done()
                        
                        # Fetch new UNSEEN messages
                        messages = server.search("UNSEEN")
                        if messages:
                            emails_data = []
                            fetch_data = server.fetch(messages, ["RFC822"])
                            for msg_id, data in fetch_data.items():
                                raw_email = data[b'RFC822']
                                emails_data.append(parse_imapclient_message(raw_email))
                            if emails_data:
                                callback(emails_data)
                                
                        # Re-enter IDLE
                        server.idle()
                        
        except Exception as e:
            logger.error(f"IMAP IDLE error: {e}")
            time.sleep(10)
"""
    content += new_func
    
    with open("services/imap_client.py", "w", encoding="utf-8") as f:
        f.write(content)

modify_routes()
modify_main()
modify_imap_client()
