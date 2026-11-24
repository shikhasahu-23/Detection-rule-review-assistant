from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.attack import AttackTechnique
from app.models.intelligence import FeedRun
from app.services.mitre_attack import sync_attack_catalog


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def sample_bundle():
    return {"objects": [
        {
            "type": "attack-pattern", "id": "attack-pattern--123",
            "name": "PowerShell", "description": "Adversaries may abuse PowerShell.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "x_mitre_platforms": ["Windows"], "x_mitre_is_subtechnique": True,
            "modified": "2025-01-01T00:00:00.000Z",
        },
        {"type": "malware", "id": "malware--1", "name": "Not a technique"},
    ]}


def test_attack_catalog_imports_techniques_and_metadata():
    db = make_session()
    result = sync_attack_catalog(db, sample_bundle())
    assert result["records_seen"] == 1
    assert result["techniques_created"] == 1
    technique = db.scalar(select(AttackTechnique).where(AttackTechnique.external_id == "T1059.001"))
    assert technique.name == "PowerShell"
    assert technique.tactics == ["Execution"]
    assert technique.platforms == ["Windows"]
    assert technique.is_subtechnique is True
    assert db.scalar(select(FeedRun).where(FeedRun.status == "succeeded")) is not None


def test_attack_catalog_sync_updates_existing_techniques():
    db = make_session()
    first = sync_attack_catalog(db, sample_bundle())
    second = sync_attack_catalog(db, sample_bundle())
    assert first["techniques_created"] == 1
    assert second["techniques_created"] == 0
    assert second["techniques_updated"] == 1
    assert len(db.scalars(select(AttackTechnique)).all()) == 1


def test_attack_catalog_rejects_invalid_stix_bundle():
    db = make_session()
    try:
        sync_attack_catalog(db, {"invalid": []})
    except TypeError:
        pass
    else:
        raise AssertionError("invalid STIX bundle should fail")
    assert db.scalar(select(FeedRun).where(FeedRun.status == "failed")) is not None
