from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.threat_graph import ThreatEntity, ThreatRelationship
from app.services.threat_graph import import_stix_bundle


def make_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def sample_bundle():
    return {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-4111-8111-111111111111",
                "name": "Example Threat Actor",
                "description": "A test actor from a trusted fixture.",
                "confidence": 85,
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-02-01T00:00:00Z",
                "external_references": [{"source_name": "Example", "url": "https://example.org/actor"}],
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--22222222-2222-4222-8222-222222222222",
                "name": "Example Malware",
                "is_family": True,
                "confidence": 70,
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--33333333-3333-4333-8333-333333333333",
                "relationship_type": "uses",
                "source_ref": "threat-actor--11111111-1111-4111-8111-111111111111",
                "target_ref": "malware--22222222-2222-4222-8222-222222222222",
                "confidence": 90,
                "description": "Source reports actor uses malware.",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--44444444-4444-4444-8444-444444444444",
                "relationship_type": "uses",
                "source_ref": "threat-actor--11111111-1111-4111-8111-111111111111",
                "target_ref": "malware--99999999-9999-4999-8999-999999999999",
            },
            {"type": "identity", "id": "identity--55555555-5555-4555-8555-555555555555", "name": "Ignored"},
        ],
    }


def test_stix_import_creates_entities_and_provenance_backed_relationships():
    db = make_session()
    result = import_stix_bundle(db, sample_bundle(), source_name="Partner CTI")
    entities = db.scalars(select(ThreatEntity).order_by(ThreatEntity.entity_type)).all()
    relationships = db.scalars(select(ThreatRelationship)).all()

    assert result["entities_created"] == 2
    assert result["relationships_created"] == 1
    assert result["objects_skipped"] == 1
    assert len(entities) == 2
    assert entities[0].source_name == "Partner CTI"
    assert entities[0].confidence == 70 or entities[0].confidence == 85
    assert relationships[0].relationship_type == "uses"
    assert relationships[0].confidence == 90
    assert relationships[0].assertion_status == "source_observed"
    assert relationships[0].source_reference.startswith("relationship--")


def test_stix_import_is_idempotent_and_updates_existing_records():
    db = make_session()
    first = import_stix_bundle(db, sample_bundle(), source_name="Partner CTI")
    second = import_stix_bundle(db, sample_bundle(), source_name="Partner CTI")

    assert first["entities_created"] == 2
    assert first["relationships_created"] == 1
    assert second["entities_created"] == 0
    assert second["entities_updated"] == 2
    assert second["relationships_created"] == 0
    assert second["relationships_updated"] == 1
    assert len(db.scalars(select(ThreatEntity)).all()) == 2
    assert len(db.scalars(select(ThreatRelationship)).all()) == 1


def test_stix_import_rejects_invalid_or_oversized_bundle():
    db = make_session()
    try:
        import_stix_bundle(db, {"type": "bundle", "objects": []}, source_name="Partner CTI")
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("empty STIX bundle must be rejected")

    try:
        import_stix_bundle(
            db, {"type": "bundle", "spec_version": "2.0", "objects": [{}]},
            source_name="Partner CTI",
        )
    except ValueError as exc:
        assert "2.1" in str(exc)
    else:
        raise AssertionError("STIX 2.0 bundle must be rejected")


def test_stix_relationship_requires_both_endpoint_entities():
    db = make_session()
    bundle = sample_bundle()
    bundle["objects"] = [bundle["objects"][2]]
    result = import_stix_bundle(db, bundle, source_name="Partner CTI")
    assert result["relationships_created"] == 0
    assert result["objects_skipped"] == 1
