from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017/"
    mongo_db_name: str = "email_intelligence_db"
    jwt_secret_key: str = "supersecretkey_please_change_in_production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    imap_server: str = ""
    imap_user: str = ""
    imap_pass: str = ""
    allowed_origin: str = "*"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
