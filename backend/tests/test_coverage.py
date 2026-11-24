from app.services.coverage import score_telemetry_coverage


def test_coverage_scores_required_fields_using_whole_tokens():
    intent = {"required_telemetry": [{
        "source": "endpoint",
        "required_fields": ["process_name", "command_line", "destination_ip"],
    }]}
    result = score_telemetry_coverage(
        intent, "search index=endpoint process_name=powershell.exe command_line=*download*"
    )
    assert result["score"] == 67
    assert result["status"] == "moderate"
    assert result["matched_requirements"] == 2
    assert result["total_requirements"] == 3
    assert result["requirements"][2]["present"] is False


def test_coverage_does_not_match_field_substrings():
    result = score_telemetry_coverage(
        {"required_telemetry": [{"source": "endpoint", "required_fields": ["user"]}]},
        "search index=endpoint username=alice",
    )
    assert result["score"] == 0
    assert result["status"] == "low"


def test_coverage_reports_unassessed_when_no_explicit_requirements():
    result = score_telemetry_coverage({}, "search index=endpoint")
    assert result["score"] is None
    assert result["status"] == "not_assessed"
