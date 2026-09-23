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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
