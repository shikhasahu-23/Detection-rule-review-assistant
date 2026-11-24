import pytest

from app.schemas.detection import TargetPlatform
from app.services.validation import validate_candidate


@pytest.mark.parametrize(
    ("platform", "query", "expected"),
    [
        (TargetPlatform.SPLUNK, "search index=endpoint", "passed_with_warnings"),
        (TargetPlatform.SENTINEL, "DeviceProcessEvents | where FileName == \"powershell.exe\"", "passed_with_warnings"),
        (TargetPlatform.CHRONICLE, "rule test { events: $e.metadata.event_type = \"PROCESS_LAUNCH\" condition: $e }", "passed_with_warnings"),
        (TargetPlatform.CROWDSTRIKE, "event_simpleName=ProcessRollup2", "passed_with_warnings"),
    ],
)
def test_valid_platform_shapes_remain_non_deployable(platform, query, expected):
    report = validate_candidate(platform, query)
    assert report["status"] == expected
    assert report["is_deployable"] is False


@pytest.mark.parametrize(
    "query",
    [
        "```spl\nsearch index=endpoint\n```",
        "search index=endpoint TODO: add filter",
        "search index=endpoint (process_name=\"powershell.exe\"",
    ],
)
def test_static_validation_rejects_obvious_draft_defects(query):
    report = validate_candidate(TargetPlatform.SPLUNK, query)
    assert report["status"] == "failed"
    assert report["errors"]
    assert report["is_deployable"] is False
