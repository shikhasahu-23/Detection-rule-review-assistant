from uuid import UUID

from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def record_audit_event(
    db: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID | None,
    action: str,
    target_type: str,
    target_id: str | None = None,
    correlation_id: str | None = None,
    metadata: dict | None = None,
) -> AuditEvent:
    """Append an audit event in the caller's transaction; never update prior events."""
    event = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        correlation_id=correlation_id,
        event_metadata=metadata or {},
    )
    db.add(event)
    db.flush()
    return event
