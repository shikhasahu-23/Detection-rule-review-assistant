"""Execution history for scheduled intelligence-to-detection pipelines."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String(24), default="running", nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="scheduled", nullable=False)
    stage_results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    indicators_enriched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    opportunities_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    candidates_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    candidates_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
