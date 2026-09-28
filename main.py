import asyncio
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from rate_limiter import limiter
from api.routes import router as api_router, run_analysis
from api.auth import router as auth_router
from database import Database
from security_headers import SecurityHeadersMiddleware

# Configured before anything else runs - without this, the root logger has
# no handler at all, so every logger.info()/logger.warning() call across
# the app (DB connection status, GeoIP fallback notices, threat-intel
# failures, rate-limit warnings...) is silently swallowed in production.
# LOG_LEVEL lets an operator turn up verbosity (e.g. DEBUG) without a code
# change.
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger(__name__)

async def imap_worker():
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
            await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if os.getenv("ENV") == "production":
        from config import settings
        default_admin_hash = "$2b$12$LrExbvOTRgBRZqisfyGKUOlvCEBTXyAa2qFDek8yt6Vems7UrZiWK"
        default_analyst_hash = "$2b$12$0cVHZzt7RqT5BTAgNZZbbOybx4plrJklXewhawpsSNlV9943DyTxG"
        # Compared against (never used as) the live secret, specifically to
        # refuse startup if the shipped .env.example default wasn't rotated.
        default_jwt_secret = "supersecretkey_please_change_in_production"  # nosec B105
        if settings.admin_password_hash == default_admin_hash:
            raise RuntimeError("CRITICAL SECURITY ERROR: Default admin credentials detected in production environment!")
        if settings.analyst_password_hash == default_analyst_hash:
            raise RuntimeError("CRITICAL SECURITY ERROR: Default analyst credentials detected in production environment!")
        if settings.jwt_secret_key == default_jwt_secret:
            raise RuntimeError("CRITICAL SECURITY ERROR: Default JWT_SECRET_KEY detected in production environment! Tokens are forgeable until this is rotated.")
            
    await Database.connect_db()
    from api.routes import manager
    await manager.connect_redis()
    asyncio.create_task(imap_worker())
    yield
    # Shutdown
    await Database.close_db()

app = FastAPI(
    title="MailTrail Threat API",
    description="An explainable, multi-signal email threat detection and forensic intelligence platform built for SIH26106.",
    version="1.0.0",
    contact={
        "name": "SIH26106 Team",
        "url": "https://github.com/mohamedbaasil25/MailTrail",
    },
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS Middleware for strict origins
origins = os.getenv("ALLOWED_ORIGIN", "http://localhost:8000,http://127.0.0.1:8000").split(",")

# A wildcard origin combined with allow_credentials=True is not just
# insecure, it's non-functional: browsers refuse to honor credentialed
# (cookie-based) requests against "*". Since this app relies on an
# httponly cookie for auth, silently keeping allow_credentials=True here
# would just break login cross-origin. Fail loudly instead so a real
# origin list gets configured before this ships anywhere.
if "*" in origins:
    if os.getenv("ENV") == "production":
        raise RuntimeError("CRITICAL SECURITY ERROR: ALLOWED_ORIGIN='*' is not permitted in production alongside cookie-based auth. Set an explicit comma-separated list of trusted origins.")
    logging.warning("ALLOWED_ORIGIN is '*' - cookie-based auth will not work cross-origin in real browsers. Set explicit origins for anything beyond local development.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials="*" not in origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Same signal used for the HSTS decision inside the middleware: only
# advertise it when we're confident this deployment sits behind TLS.
app.add_middleware(SecurityHeadersMiddleware, enable_hsts=os.getenv("ENV") == "production")

# Include API routes
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(api_router, prefix="/api/v1")

@app.get("/api/health")
async def root_health_check():
    """
    Liveness probe: is the process up and serving requests at all? Cheap
    and dependency-free on purpose - this is what a container orchestrator
    should hit to decide "should I kill/restart this process", not whether
    downstream dependencies are healthy (that's /api/v1/health).
    """
    return {"status": "healthy", "ok": True, "service": "Email Intelligence API"}

# Mount the frontend directory as static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
