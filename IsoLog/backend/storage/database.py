"""
IsoLog Database Manager

Handles database connections, initialization, and session management.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from .models import Base
from ..config import get_settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages database connections and sessions.
    
    Supports both sync and async operations for SQLite.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file. If None, uses config.
        """
        settings = get_settings()
        
        if db_path is None:
            db_path = str(settings.resolve_path(settings.database.path))
        
        self.db_path = db_path
        self._ensure_directory()
        
        # Async engine for FastAPI
        self.async_engine = create_async_engine(
            f"sqlite+aiosqlite:///{self.db_path}",
            echo=settings.database.echo,
            connect_args={"check_same_thread": False},
        )
        
        # Sync engine for background tasks
        self.sync_engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=settings.database.echo,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        
        # Session factories
        self.async_session_factory = async_sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        
        self.sync_session_factory = sessionmaker(
            self.sync_engine,
            expire_on_commit=False,
        )
        
        # Enable WAL mode for better concurrent access
        @event.listens_for(self.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.close()
    
    def _ensure_directory(self):
        """Ensure database directory exists."""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    async def init_db(self):
        """Initialize database tables."""
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Database initialized at {self.db_path}")
    
    def init_db_sync(self):
        """Initialize database tables (synchronous)."""
        Base.metadata.create_all(self.sync_engine)
        logger.info(f"Database initialized at {self.db_path}")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get async database session."""
        async with self.async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    
    def get_sync_session(self) -> Session:
        """Get sync database session."""
        return self.sync_session_factory()
    
    async def close(self):
        """Close database connections."""
        await self.async_engine.dispose()
        self.sync_engine.dispose()


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    """Get or create global database manager."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


async def init_db():
    """Initialize the database."""
    manager = get_db_manager()
    await manager.init_db()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI endpoints.
    
    Usage:
        @app.get("/events")
        async def get_events(db: AsyncSession = Depends(get_db)):
            ...
    """
    manager = get_db_manager()
    async with manager.get_session() as session:
        yield session
