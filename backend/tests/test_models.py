from app.db.base import Base
from app import models


def test_initial_model_metadata_contains_core_tables() -> None:
    expected = {
        "organizations", "users", "team_memberships", "intel_sources",
        "ingestion_runs", "intel_records", "intel_evidence", "audit_events",
    }
    assert expected.issubset(set(Base.metadata.tables))


def test_intelligence_records_are_unique_per_org_type_and_normalized_value() -> None:
    table = models.IntelRecord.__table__
    constraints = [constraint for constraint in table.constraints if constraint.__class__.__name__ == "UniqueConstraint"]
    assert any(tuple(column.name for column in item.columns) == ("organization_id", "record_type", "normalized_value") for item in constraints)


def test_evidence_preserves_multiple_sources_and_payload_identity() -> None:
    table = models.IntelEvidence.__table__
    constraints = [constraint for constraint in table.constraints if constraint.__class__.__name__ == "UniqueConstraint"]
    assert any(tuple(column.name for column in item.columns) == ("record_id", "source_id", "payload_hash") for item in constraints)
