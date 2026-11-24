"""Conservative static checks for candidate query text.

These checks are guardrails, not full vendor parsers or execution tests. A passing
result must never be interpreted as proof that a query is deployable.
"""
from app.schemas.detection import TargetPlatform


def validate_candidate(platform: TargetPlatform, query: str) -> dict:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    normalized = query.strip()
    if not normalized:
        errors.append({"code": "EMPTY_QUERY", "message": "Query cannot be empty."})
    if "\x00" in normalized:
        errors.append({"code": "NULL_BYTE", "message": "Query contains a null byte."})

    if platform is TargetPlatform.SPLUNK:
        if not normalized.lower().startswith(("search ", "|", "tstats ", "from ")):
            errors.append({
                "code": "SPL_ENTRYPOINT",
                "message": "Expected a Splunk search pipeline, such as search, tstats, from, or a leading pipe.",
            })
        warnings.append({
            "code": "SPL_STATIC_ONLY",
            "message": "Splunk syntax and field availability require validation in a representative Splunk environment.",
        })
    elif platform is TargetPlatform.SENTINEL:
        if "|" not in normalized:
            errors.append({"code": "KQL_PIPELINE", "message": "KQL query must contain a pipe-delimited operator."})
        warnings.append({
            "code": "KQL_STATIC_ONLY",
            "message": "KQL syntax and table/column availability require validation in the target Sentinel workspace.",
        })
    elif platform is TargetPlatform.CHRONICLE:
        lowered = normalized.lower()
        if "rule " not in lowered or "events:" not in lowered or "condition:" not in lowered:
            errors.append({
                "code": "YARAL_STRUCTURE",
                "message": "YARA-L 2.0 candidate must include rule, events, and condition sections.",
            })
        warnings.append({
            "code": "YARAL_STATIC_ONLY",
            "message": "YARA-L compilation and UDM field compatibility require Chronicle validation.",
        })
    elif platform is TargetPlatform.CROWDSTRIKE:
        warnings.append({
            "code": "FALCON_VALIDATION_PENDING",
            "message": "CrowdStrike query grammar validation is not enabled until the current NG-SIEM contract is verified.",
        })

    return {
        "status": "failed" if errors else "passed_with_warnings" if warnings else "passed",
        "errors": errors,
        "warnings": warnings,
        "checks_performed": ["non_empty", "null_byte", f"{platform.value}_structure"],
        "is_deployable": False,
    }
