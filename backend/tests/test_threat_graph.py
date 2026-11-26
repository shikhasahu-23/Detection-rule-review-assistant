from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.threat_graph import ThreatEntity, ThreatEntityEvidence, ThreatRelationship
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
                "severity": "critical",
                "impact": "Credential theft and lateral movement.",
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
    evidence = db.scalars(select(ThreatEntityEvidence)).all()

    assert result["entities_created"] == 2
    assert result["relationships_created"] == 1
    assert result["objects_skipped"] == 1
    assert len(entities) == 2
    assert len(evidence) == 2
    actor = next(entity for entity in entities if entity.entity_type == "threat_actor")
    assert actor.source_name == "Partner CTI"
    assert actor.confidence == 85
    assert actor.severity == "critical"
    assert actor.impact == "Credential theft and lateral movement."
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
    assert len(db.scalars(select(ThreatEntityEvidence)).all()) == 2


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



def test_entity_evidence_is_preserved_across_multiple_sources():
    db = make_session()
    bundle = sample_bundle()
    bundle["objects"] = bundle["objects"][:2]
    import_stix_bundle(db, bundle, source_name="Partner One")
    import_stix_bundle(db, bundle, source_name="Partner Two")

    entity = db.scalar(select(ThreatEntity).where(ThreatEntity.entity_type == "threat_actor"))
    evidence = db.scalars(select(ThreatEntityEvidence).where(
        ThreatEntityEvidence.entity_id == entity.id
    )).all()
    assert len(evidence) == 2
    assert {row.source_name for row in evidence} == {"Partner One", "Partner Two"}



def test_missing_stix_confidence_severity_and_impact_remain_unknown():
    db = make_session()
    bundle = sample_bundle()
    actor = bundle["objects"][0]
    actor.pop("confidence")
    actor.pop("severity")
    actor.pop("impact")
    bundle["objects"] = [actor]
    import_stix_bundle(db, bundle, source_name="Feed without scoring")

    entity = db.scalar(select(ThreatEntity))
    evidence = db.scalar(select(ThreatEntityEvidence))
    assert entity.confidence is None
    assert evidence.confidence is None
    assert entity.severity is None
    assert entity.impact is None


def test_vulnerability_severity_can_be_classified_from_explicit_cvss_score():
    db = make_session()
    bundle = {
        "type": "bundle",
        "objects": [{
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": "vulnerability--66666666-6666-4666-8666-666666666666",
            "name": "Example CVE",
            "x_cvss_v3_base_score": 9.8,
        }],
    }
    import_stix_bundle(db, bundle, source_name="NVD-like source")
    entity = db.scalar(select(ThreatEntity))
    assert entity.severity == "critical"
    assert entity.confidence is None
    assert entity.impact is None
