import os
from typing import Optional
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
    # Bắt buộc cung cấp qua biến môi trường ở môi trường triển khai, loại bỏ fallback mặc định
    AES_MASTER_KEY_HEX: Optional[str] = (
        os.getenv("GITPROTECT_AES_MASTER_KEY") or os.getenv("AES_MASTER_KEY_HEX")
    )
    
    ALLOWED_EMAIL_DOMAINS: list[str] = [
        d.strip() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "organization.vn,gitprotect.io").split(",")
    ]

settings = Settings()
