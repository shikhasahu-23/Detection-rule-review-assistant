from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.attack import AttackTechnique
from app.models.detection import DetectionIntent
from app.models.rule import RuleCandidate
from app.models.testing import DetectionTestRun
from app.services.effectiveness import build_detection_effectiveness

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine)


def test_effectiveness_uses_explicit_attack_mapping_and_surfaces_gaps():
    with Session(engine) as db:
        technique = AttackTechnique(
            stix_id="attack-pattern--11111111-1111-4111-8111-111111111111",
            external_id="T1059.001", name="PowerShell", description="Execution",
            platforms=["Windows"], tactics=["execution"], source_url="https://attack.mitre.org/techniques/T1059/001/",
        )
        mapped = DetectionIntent(
            title="PowerShell execution", description="Detect PowerShell execution.",
            behavior="Detect suspicious PowerShell execution.", severity="high",
            attack_techniques=["T1059.001"], required_telemetry=[{"source":"endpoint","required_fields":["process_name"]}],
            evidence=[], test_scenarios=[], target_platforms=["splunk"], status="draft",
        )
        unmapped = DetectionIntent(
            title="Unmapped behavior", description="An unmapped behavior.",
            behavior="Detect a different suspicious behavior.", severity="medium",
            attack_techniques=[], required_telemetry=[], evidence=[], test_scenarios=[],
            target_platforms=["sentinel"], status="draft",
        )
        db.add_all([technique, mapped, unmapped])
        db.flush()
        candidate = RuleCandidate(
            intent_id=mapped.id, name="PowerShell", platform="splunk",
            query="search index=endpoint process_name=powershell.exe", version=1,
            status="candidate", validation_status="passed",
            validation_report={"telemetry_coverage":{"score":100}},
            generation_metadata={}, generator="manual",
        )
        db.add(candidate)
        db.flush()
        db.add(DetectionTestRun(
            candidate_id=candidate.id, suite_fingerprint="a"*64, query_fingerprint="b"*64,
            status="passed", total_cases=2, passed_cases=2, failed_cases=0,
            case_results=[{"name":"positive","status":"passed"},{"name":"negative","status":"passed"}],
            regression_report={"status":"baseline"},
        ))
        db.commit()

        result = build_detection_effectiveness(db)
        assert result["summary"]["active_techniques"] == 1
        assert result["summary"]["covered_techniques"] == 1
        assert result["summary"]["coverage_percent"] == 100
        assert result["summary"]["intents_with_candidates"] == 1
        mapped_row = next(row for row in result["detections"] if row["title"] == "PowerShell execution")
        assert mapped_row["readiness_score"] == 100
        assert mapped_row["platforms"][0]["test_score"] == 100
        assert result["methodology"]["limitations"]
