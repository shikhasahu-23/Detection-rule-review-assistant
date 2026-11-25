from app.schemas.detection import TargetPlatform
from app.services.generation import GenerationUnavailable, TemplateGenerationProvider


def intent():
    return {
        "title": "Suspicious PowerShell download",
        "description": "Detects PowerShell downloading executable content from external hosts.",
        "behavior": "PowerShell retrieves a remote payload using a download command.",
        "required_telemetry": [{
            "source": "endpoint",
            "description": "Process creation events",
            "required_fields": ["process_name", "command_line", "parent_process_name"],
        }],
    }


def test_free_splunk_template_uses_only_supplied_fields():
    result = TemplateGenerationProvider().generate(intent(), TargetPlatform.SPLUNK)
    assert result.query.startswith("search ")
    assert "process_name=*" in result.query
    assert "command_line=*" in result.query
    assert "powershell" in result.query.lower()
    assert "index=" not in result.query


def test_free_sentinel_template_maps_common_fields():
    result = TemplateGenerationProvider().generate(intent(), TargetPlatform.SENTINEL)
    assert result.query.startswith("DeviceProcessEvents")
    assert "ProcessCommandLine" in result.query
    assert "FileName" in result.query
    assert "InitiatingProcessFileName" in result.query


def test_free_chronicle_template_has_required_sections():
    result = TemplateGenerationProvider().generate(intent(), TargetPlatform.CHRONICLE)
    assert "rule threatweave_template_rule" in result.query
    assert "events:" in result.query
    assert "condition:" in result.query


def test_free_template_does_not_fabricate_crowdstrike_query():
    try:
        TemplateGenerationProvider().generate(intent(), TargetPlatform.CROWDSTRIKE)
    except GenerationUnavailable as exc:
        assert "not available" in str(exc)
    else:
        raise AssertionError("CrowdStrike template generation must remain disabled")


def test_free_template_requires_telemetry_fields():
    data = intent()
    data["required_telemetry"] = []
    try:
        TemplateGenerationProvider().generate(data, TargetPlatform.SPLUNK)
    except GenerationUnavailable as exc:
        assert "required telemetry field" in str(exc)
    else:
        raise AssertionError("Template generation must require explicit telemetry fields")
