from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.intelligence import Indicator
from app.models.rule import RuleCandidate
from app.schemas.detection import TargetPlatform
from app.services.generation import TemplateGenerationProvider
from app.services.ioc_rule_sync import sync_ioc_rules
from app.services.validation import validate_candidate


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


def test_sigma_yaml_and_cve_rules_are_generated_for_supported_formats():
    provider = TemplateGenerationProvider()
    intent = {
        "title": "Active CVE coverage",
        "description": "Detect vulnerable software",
        "behavior": "Match active CVE identifiers",
        "required_telemetry": [{"source": "vulnerability", "required_fields": ["indicator_value"]}],
        "indicator_type": "cve",
        "indicator_values": ["CVE-2025-12345", "CVE-2026-98765"],
    }
    sigma = provider.generate(intent, TargetPlatform.SIGMA)
    report = validate_candidate(TargetPlatform.SIGMA, sigma.query, intent)
    assert not report["errors"]
    assert "CVE-2025-12345" in sigma.query

    splunk = provider.generate(intent, TargetPlatform.SPLUNK)
    sentinel = provider.generate(intent, TargetPlatform.SENTINEL)
    chronicle = provider.generate(intent, TargetPlatform.CHRONICLE)
    assert "CVE-2025-12345" in splunk.query
    assert "DeviceTvmSoftwareVulnerabilities" in sentinel.query
    assert "$e.vulnerability.cve_id" in chronicle.query



def test_cve_ioc_rules_are_grouped_by_cwe_weakness_category():
    db = make_session()
    db.add_all([
        Indicator(indicator_type="cve", value="CVE-2025-0001", confidence=90, severity="high", status="active", tags=["nvd", "vulnerability", "cwe:CWE-79"]),
        Indicator(indicator_type="cve", value="CVE-2025-0002", confidence=90, severity="high", status="active", tags=["nvd", "vulnerability", "cwe:CWE-79"]),
        Indicator(indicator_type="cve", value="CVE-2025-0003", confidence=90, severity="high", status="active", tags=["nvd", "vulnerability", "cwe:CWE-89"]),
        Indicator(indicator_type="cve", value="CVE-2025-0004", confidence=90, severity="high", status="active", tags=["nvd", "vulnerability"]),
    ])
    db.commit()

    result = sync_ioc_rules(db)
    intents = db.scalars(select(__import__("app.models.detection", fromlist=["DetectionIntent"]).DetectionIntent)).all()
    titles = {item.title for item in intents}
    assert result["rule_versions_created"] == 16
    assert "ThreatWeave Active IOC Coverage: cve-cwe-79:0001" in titles
    assert "ThreatWeave Active IOC Coverage: cve-cwe-89:0001" in titles
    assert "ThreatWeave Active IOC Coverage: cve-unclassified:0001" in titles
    cwe79_rules = db.scalars(select(RuleCandidate).where(RuleCandidate.intent_id == next(
        item.id for item in intents if item.title.endswith("cve-cwe-79:0001")
    ))).all()
    assert len(cwe79_rules) == 4
    assert all("CVE-2025-0001" in item.query and "CVE-2025-0002" in item.query for item in cwe79_rules)
    assert all("CVE-2025-0003" not in item.query for item in cwe79_rules)
