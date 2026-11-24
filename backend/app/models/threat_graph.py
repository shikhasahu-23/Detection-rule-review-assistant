"""Source-backed threat entities and relationships."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatEntity(Base):
    __tablename__ = "threat_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "external_id", name="uq_threat_entity_type_external_id"),
        Index("ix_threat_entities_type_name", "entity_type", "name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    revoked: Mapped[bool] = mapped_column(default=False, nullable=False)
    deprecated: Mapped[bool] = mapped_column(default=False, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatRelationship(Base):
    __tablename__ = "threat_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_entity_id", "target_entity_id", "relationship_type",
            "source_name", "source_reference", name="uq_threat_relationship_evidence",
        ),
        Index("ix_threat_relationship_source", "source_entity_id"),
        Index("ix_threat_relationship_target", "target_entity_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_entities.id", ondelete="CASCADE"), nullable=False
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_entities.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    assertion_status: Mapped[str] = mapped_column(String(32), default="source_observed", nullable=False)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
