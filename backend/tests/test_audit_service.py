from uuid import uuid4

from app.services.audit import record_audit_event


class FakeSession:
    def __init__(self) -> None:
        self.added = None
        self.flushed = False

    def add(self, value) -> None:
        self.added = value

    def flush(self) -> None:
        self.flushed = True


def test_audit_service_appends_event_and_flushes_without_committing() -> None:
    session = FakeSession()
    event = record_audit_event(
        session, organization_id=uuid4(), actor_user_id=None,
        action="intel.source.created", target_type="intel_source",
        target_id="source-123", metadata={"source": "test"},
    )
    assert session.added is event
    assert session.flushed is True
    assert event.action == "intel.source.created"
    assert event.event_metadata == {"source": "test"}
