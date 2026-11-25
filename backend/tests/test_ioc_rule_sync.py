from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import Indicator
from app.models.rule import RuleCandidate
from app.services.ioc_rule_sync import sync_ioc_rules


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_active_iocs_generate_all_supported_rule_languages_and_are_idempotent():
    db = make_session()
    db.add_all([
        Indicator(indicator_type="ip", value="203.0.113.10", confidence=90, severity="high", status="active", tags=[]),
        Indicator(indicator_type="ip", value="198.51.100.20", confidence=85, severity="high", status="active", tags=[]),
        Indicator(indicator_type="domain", value="bad.example", confidence=95, severity="high", status="active", tags=[]),
    ])
    db.commit()

    first = sync_ioc_rules(db)
    assert first["rule_versions_created"] == 8
    rules = db.scalars(select(RuleCandidate)).all()
    assert {rule.platform for rule in rules} == {"splunk", "sentinel", "chronicle", "sigma"}
    assert all(rule.status == "candidate" for rule in rules)
    assert all(rule.validation_report["is_deployable"] is False for rule in rules)
    assert any("203.0.113.10" in rule.query for rule in rules)

    second = sync_ioc_rules(db)
    assert second["rule_versions_created"] == 0
    assert second["unchanged_platform_rules_skipped"] == 8
    assert len(db.scalars(select(RuleCandidate)).all()) == 8


def test_new_active_ioc_creates_new_versions_without_overwriting_history():
    db = make_session()
    db.add(Indicator(indicator_type="ip", value="203.0.113.10", confidence=90, severity="high", status="active", tags=[]))
    db.commit()
    sync_ioc_rules(db)
    db.add(Indicator(indicator_type="ip", value="198.51.100.20", confidence=90, severity="high", status="active", tags=[]))
    db.commit()

    result = sync_ioc_rules(db)
    assert result["rule_versions_created"] == 4
    versions = db.scalars(select(RuleCandidate).where(RuleCandidate.platform == "sigma").order_by(RuleCandidate.version)).all()
    assert [item.version for item in versions] == [1, 2]
    assert "198.51.100.20" not in versions[0].query
    assert "198.51.100.20" in versions[1].query
