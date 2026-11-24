from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.attack import AttackTechnique
from app.models.detection import DetectionIntent
from app.models.intelligence import Indicator, SourceEvidence
from app.services.enrichment import detection_opportunities, enrich_indicator


def make_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def test_enrichment_uses_exact_attack_and_cve_evidence_references():
    db = make_session()
    indicator = Indicator(
        indicator_type="cve", value="CVE-2025-12345", confidence=95,
        severity="high", status="active", tags=["known-exploited"],
    )
    db.add(indicator)
    db.flush()
    db.add(SourceEvidence(
        indicator_id=indicator.id, source_name="Partner Intel",
        source_reference="partner-CVE-2025-12345-T1059.001",
        raw_data={"observed_technique": "T1059.001"},
    ))
    db.add(AttackTechnique(
        stix_id="attack-pattern--test", external_id="T1059.001",
        name="PowerShell", description="PowerShell execution",
        platforms=["Windows"], tactics=["Execution"],
        source_url="https://attack.mitre.org/techniques/T1059/001/",
    ))
    intent = DetectionIntent(
        title="PowerShell execution", description="Detect suspicious PowerShell activity",
        behavior="PowerShell used to execute suspicious commands",
        severity="high", attack_techniques=["T1059.001"],
        required_telemetry=[{"source": "endpoint"}], evidence=[
            {"kind": "cve", "reference": "CVE-2025-12345", "source": "Partner Intel", "confidence": 90}
        ],
        test_scenarios=[], target_platforms=["splunk"], status="draft",
    )
    db.add(intent)
    db.commit()

    result = enrich_indicator(db, indicator.id)
    assert result is not None
    assert result["attack_techniques"][0]["external_id"] == "T1059.001"
    assert result["detection_intents"][0]["intent_id"] == str(intent.id)
    assert result["detection_intents"][0]["matched_techniques"] == ["T1059.001"]
    assert result["detection_intents"][0]["matched_cves"] == ["CVE-2025-12345"]
    assert result["correlation_method"].startswith("exact references only")


def test_unrelated_indicator_does_not_get_heuristic_intent_association():
    db = make_session()
    indicator = Indicator(
        indicator_type="domain", value="example.invalid", confidence=50,
        severity="unknown", status="active", tags=["malware"],
    )
    intent = DetectionIntent(
        title="Unrelated detection", description="An unrelated detection description",
        behavior="Detect a behavior without an explicit intelligence reference",
        severity="medium", attack_techniques=["T1059.001"],
        required_telemetry=[{"source": "endpoint"}], evidence=[],
        test_scenarios=[], target_platforms=["splunk"], status="draft",
    )
    db.add_all([indicator, intent])
    db.commit()

    result = enrich_indicator(db, indicator.id)
    assert result is not None
    assert result["detection_intents"] == []
    assert detection_opportunities(db) == []


def test_detection_opportunities_group_evidence_backed_matches():
    db = make_session()
    indicator = Indicator(
        indicator_type="cve", value="CVE-2025-12345", confidence=95,
        severity="critical", status="active", tags=[],
    )
    intent = DetectionIntent(
        title="Exploit activity", description="Detect exploitation of tracked vulnerabilities",
        behavior="Identify exploitation linked to CVE-2025-12345",
        severity="critical", attack_techniques=[],
        required_telemetry=[{"source": "network"}],
        evidence=[{"kind": "cve", "reference": "CVE-2025-12345", "source": "NVD", "confidence": 90}],
        test_scenarios=[], target_platforms=["chronicle"], status="draft",
    )
    db.add_all([indicator, intent])
    db.commit()

    results = detection_opportunities(db)
    assert len(results) == 1
    assert results[0]["intent_id"] == str(intent.id)
    assert results[0]["indicator_count"] == 1
    assert results[0]["matched_cves"] == ["CVE-2025-12345"]
    assert results[0]["association_type"] == "explicit_reference"
