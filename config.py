from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017/"
    mongo_db_name: str = "email_intelligence_db"
    jwt_secret_key: str  # Required parameter, no default
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    imap_server: str = ""
    imap_user: str = ""
    imap_pass: str = ""
    allowed_origin: str = "*"
    
    # Admin Credentials
    admin_username: str = "admin"
    admin_password_hash: str = "$2b$12$LrExbvOTRgBRZqisfyGKUOlvCEBTXyAa2qFDek8yt6Vems7UrZiWK"
    analyst_username: str = "analyst"
    analyst_password_hash: str = "$2b$12$0cVHZzt7RqT5BTAgNZZbbOybx4plrJklXewhawpsSNlV9943DyTxG"
    enable_heavy_nlp: bool = True

    # External Threat Intelligence (VirusTotal-compatible v3 API)
    threat_intel_api_key: str = ""
    threat_intel_base_url: str = "https://www.virustotal.com/api/v3"
    threat_intel_timeout_seconds: float = 6.0
    threat_intel_max_retries: int = 2
    threat_intel_max_indicators: int = 5  # cap external calls per email analyzed

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
