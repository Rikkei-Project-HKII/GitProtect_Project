"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Database Session & Connection Engine Configuration
"""

import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings


def get_database_url() -> str:
    """
    Constructs the database connection string.
    Prioritizes DATABASE_URL environment variable if set.
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    return (
        f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}"
        f"@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}?charset=utf8mb4"
    )


DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=10,
    max_overflow=20,
    echo=False,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a SQLAlchemy session.
    Ensures safe session closure after request handling.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
