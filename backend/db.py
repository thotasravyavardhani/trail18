"""
Database configuration and session management for QuMail
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
import aiosqlite
import asyncio
from typing import Generator

from models import Base

# SQLite database URL
DATABASE_URL = "sqlite:///./qumail.db"

# Create SQLite engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30
    },
    poolclass=StaticPool,
    echo=False  # Set to True for SQL debugging
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

async def init_db():
    """Initialize database tables"""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise

def get_db() -> Generator[Session, None, None]:
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_async_db():
    """Get async database connection for background tasks"""
    async with aiosqlite.connect("qumail.db") as db:
        yield db

class DatabaseManager:
    """Database operations manager with transaction support"""
    
    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()
    
    def execute_transaction(self, func, *args, **kwargs):
        """Execute function within a database transaction"""
        session = self.get_session()
        try:
            result = func(session, *args, **kwargs)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    async def execute_async_transaction(self, func, *args, **kwargs):
        """Execute async function within a database transaction"""
        session = self.get_session()
        try:
            result = await func(session, *args, **kwargs)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            session = self.get_session()
            session.execute("SELECT 1")
            session.close()
            return True
        except Exception:
            return False

# Global database manager instance
db_manager = DatabaseManager()