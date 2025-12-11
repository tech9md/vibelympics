"""SQLAlchemy database models."""
from sqlalchemy import Column, String, Float, Integer, DateTime, Text, JSON
from sqlalchemy.sql import func
from app.db.database import Base
import uuid


def generate_uuid():
    return str(uuid.uuid4())


class Audit(Base):
    """Audit job record."""
    __tablename__ = "audits"

    id = Column(String, primary_key=True, default=generate_uuid)
    package_name = Column(String, nullable=False, index=True)
    package_version = Column(String, nullable=True)
    status = Column(String, default="queued")
    progress = Column(Integer, default=0)
    current_analyzer = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Results
    overall_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    report_data = Column(JSON, nullable=True)


class PackageCache(Base):
    """Cached package metadata."""
    __tablename__ = "package_cache"

    id = Column(String, primary_key=True, default=generate_uuid)
    package_name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True)
    data = Column(JSON, nullable=False)
    cached_at = Column(DateTime, server_default=func.now())
