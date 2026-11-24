import json
from pathlib import Path

import pytest

from app.schemas.detection import TargetPlatform
from app.services.validation import validate_candidate

FIXTURES = Path(__file__).parent / "fixtures" / "detection_queries"


@pytest.mark.parametrize("platform", list(TargetPlatform))
def test_platform_query_fixture_validation(platform):
    fixture = json.loads((FIXTURES / f"{platform.value}.json").read_text())
    report = validate_candidate(platform, fixture["query"])
    assert report["status"] == fixture["expected_validation"]
    assert report["is_deployable"] is False
