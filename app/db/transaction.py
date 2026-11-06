"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Atomic Database Transaction Context Manager (AC-04)
"""

from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy.orm import Session
from app.db.session import SessionLocal


@contextmanager
def transaction_scope(session: Optional[Session] = None) -> Generator[Session, None, None]:
    """
    Context manager for atomic database transactions.
    
    If an existing session is provided, it manages transaction commit/rollback
    without closing the session (for caller reuse).
    If no session is provided, it instantiates a SessionLocal, commits on success,
    rolls back on error, and ensures the session is closed in the finally block.
    
    Usage:
        with transaction_scope(db) as s:
            s.add(model_instance)
            # Automatic commit on exit, rollback on exception
    """
    if session is not None:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
    else:
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
