import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "GitProtect MVP"
    VERSION: str = "1.1.0"
    API_V1_STR: str = "/api/v1"
    
    MYSQL_HOST: str = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT: int = int(os.getenv("MYSQL_PORT", 3306))
    MYSQL_USER: str = os.getenv("MYSQL_USER", "gitprotect_user")
    MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "gitprotect_pass")
    MYSQL_DB: str = os.getenv("MYSQL_DB", "gitprotect_db")
    
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    
    # Master Key for AES-256-GCM (32 bytes hex or url-safe string)
    AES_MASTER_KEY_HEX: str = os.getenv(
        "AES_MASTER_KEY_HEX",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    
    ALLOWED_EMAIL_DOMAINS: list[str] = [
        d.strip() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "organization.vn,gitprotect.io").split(",")
    ]

settings = Settings()
