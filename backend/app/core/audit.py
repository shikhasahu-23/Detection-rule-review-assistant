from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def record_audit_event(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID | None,
    action: str,
    target_type: str,
    target_id: str,
    event_metadata: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> AuditEvent:
    """Add an audit event to the caller's transaction; callers must commit with the action."""
    event = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        event_metadata=event_metadata or {},
        correlation_id=correlation_id,
    )
    session.add(event)
    return event
