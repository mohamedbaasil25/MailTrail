import asyncio
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from api.routes import router as api_router
from api.auth import router as auth_router
from api.routes import analyze_email
from database import Database

# Set up Rate Limiter
limiter = Limiter(key_func=get_remote_address)

async def imap_worker():
    imap_server = os.getenv("IMAP_SERVER")
    username = os.getenv("IMAP_USER")
    password = os.getenv("IMAP_PASS")
    
    if not all([imap_server, username, password]):
        logging.info("IMAP credentials not set. Automated inbox scanning is disabled.")
        return
        
    logging.info("Starting automated IMAP scanning...")
    while True:
        try:
            from services.imap_client import fetch_emails_via_imap
            loop = asyncio.get_running_loop()
            emails = await loop.run_in_executor(None, fetch_emails_via_imap, imap_server, username, password, "inbox", 5)
            
            for email in emails:
                try:
                    await analyze_email(email)
                except Exception as e:
                    logging.error(f"Error analyzing fetched email: {e}")
        except Exception as e:
            logging.error(f"IMAP Worker error: {e}")
            
        await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await Database.connect_db()
    asyncio.create_task(imap_worker())
    yield
    # Shutdown
    await Database.close_db()

app = FastAPI(
    title="Email Intelligence API",
    description="API for AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS Middleware for strict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGIN", "*")], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(api_router, prefix="/api/v1")

# Mount the frontend directory as static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
def read_root():
    return FileResponse("frontend/index.html")
