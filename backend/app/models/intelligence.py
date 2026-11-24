from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("indicator_type", "value", name="uq_indicator_type_value"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    severity: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SourceEvidence(Base):
    __tablename__ = "source_evidence"
    __table_args__ = (
        UniqueConstraint(
            "indicator_id", "source_name", "source_reference", name="uq_indicator_source_ref"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)


class FeedRun(Base):
    __tablename__ = "feed_runs"
    __table_args__ = (Index("ix_feed_runs_source_started", "source_name", "started_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    indicators_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    evidence_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
