from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RuleCandidate(Base):
    __tablename__ = "rule_candidates"
    __table_args__ = (
        UniqueConstraint("intent_id", "platform", "version", name="uq_rule_candidate_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    intent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detection_intents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="candidate", nullable=False, index=True)
    validation_status: Mapped[str] = mapped_column(String(24), default="not_run", nullable=False)
    validation_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    generator: Mapped[str] = mapped_column(String(80), default="manual", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
