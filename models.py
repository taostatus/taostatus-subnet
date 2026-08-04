from __future__ import annotations

"""SQLAlchemy ORM models for the forecasting validator."""

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship


Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: Optional[Any]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Task(Base):
    __tablename__ = "tasks"

    task_id = Column(String, primary_key=True)
    question = Column(Text, nullable=False)
    category = Column(String, nullable=False, default="general")
    deadline = Column(DateTime(timezone=True), nullable=False, index=True)
    resolution_hint = Column(Text, nullable=False, default="")
    source = Column(String, nullable=False)
    schema_version = Column(String, nullable=False, default="1.0")
    status = Column(String, nullable=False, default="open", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    submissions = relationship("Submission", back_populates="task")
    resolution = relationship("Resolution", back_populates="task", uselist=False)


class Submission(Base):
    __tablename__ = "submissions"
    __table_args__ = (
        UniqueConstraint("task_id", "miner_uid", name="uq_submission_task_miner"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String, ForeignKey("tasks.task_id"), nullable=False, index=True)
    miner_uid = Column(Integer, ForeignKey("miner_registrations.uid"), nullable=False, index=True)
    probability = Column(Float, nullable=True)
    reasoning = Column(Text, nullable=False, default="")
    submitted_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    status = Column(String, nullable=False, default="valid", index=True)
    rejection_kind = Column(String, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    brier_score = Column(Float, nullable=True)
    reward = Column(Float, nullable=True)
    scored_at = Column(DateTime(timezone=True), nullable=True)
    raw_response = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    task = relationship("Task", back_populates="submissions")
    miner = relationship("MinerRegistration", back_populates="submissions")


class Resolution(Base):
    __tablename__ = "resolutions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String, ForeignKey("tasks.task_id"), nullable=False, unique=True, index=True)
    outcome = Column(Float, nullable=False)
    source = Column(String, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    metadata_json = Column(JSON, nullable=True)

    task = relationship("Task", back_populates="resolution")


class MinerRegistration(Base):
    __tablename__ = "miner_registrations"

    uid = Column(Integer, primary_key=True)
    hotkey = Column(String, nullable=False, default="")
    axon = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    metadata_json = Column(JSON, nullable=True)
    registered_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    submissions = relationship("Submission", back_populates="miner")
    profile = relationship("ReliabilityProfile", back_populates="miner", uselist=False)


class ReliabilityProfile(Base):
    __tablename__ = "reliability_profiles"

    miner_uid = Column(Integer, ForeignKey("miner_registrations.uid"), primary_key=True)
    mean_brier = Column(Float, nullable=False, default=1.0)
    recent_brier = Column(Float, nullable=False, default=1.0)
    valid_count = Column(Integer, nullable=False, default=0)
    invalid_count = Column(Integer, nullable=False, default=0)
    late_missing_count = Column(Integer, nullable=False, default=0)
    calibration_buckets = Column(JSON, nullable=False, default=list)
    calibration_error = Column(Float, nullable=False, default=0.0)
    base_score = Column(Float, nullable=False, default=0.0)
    raw_weight = Column(Float, nullable=False, default=0.0)
    normalized_weight = Column(Float, nullable=False, default=0.0)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    miner = relationship("MinerRegistration", back_populates="profile")


class SyncState(Base):
    __tablename__ = "sync_state"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=True)
    etag = Column(String, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
