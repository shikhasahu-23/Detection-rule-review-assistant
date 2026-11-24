"""Conservative static checks for candidate query text.

These checks are guardrails, not full vendor parsers or execution tests. A passing
result must never be interpreted as proof that a query is deployable.
"""
from app.schemas.detection import TargetPlatform


def _balanced_delimiters(query: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    for char in query:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                return False
    return not stack and quote is None


def validate_candidate(platform: TargetPlatform, query: str) -> dict:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    normalized = query.strip()
    lowered = normalized.lower()

    if not normalized:
        errors.append({"code": "EMPTY_QUERY", "message": "Query cannot be empty."})
    if "\x00" in normalized:
        errors.append({"code": "NULL_BYTE", "message": "Query contains a null byte."})
    if normalized.startswith("\x60\x60\x60") or normalized.endswith("\x60\x60\x60"):
        errors.append({"code": "MARKDOWN_FENCE", "message": "Remove Markdown fences; store only the native query."})
    if any(token in lowered for token in ("<insert ", "todo:", "your query here", "replace_me")):
        errors.append({"code": "PLACEHOLDER", "message": "Query contains an unresolved placeholder."})
    if normalized and not _balanced_delimiters(normalized):
        errors.append({"code": "UNBALANCED_DELIMITERS", "message": "Query contains unbalanced quotes or delimiters."})

    if platform is TargetPlatform.SPLUNK:
        if not lowered.startswith(("search ", "|", "tstats ", "from ", "index=")):
            errors.append({"code": "SPL_ENTRYPOINT", "message": "Expected a Splunk search pipeline, such as index=, search, tstats, from, or a leading pipe."})
        warnings.append({"code": "SPL_STATIC_ONLY", "message": "Splunk syntax, macros, data models and field availability require validation in a representative Splunk environment."})
    elif platform is TargetPlatform.SENTINEL:
        if "|" not in normalized:
            errors.append({"code": "KQL_PIPELINE", "message": "KQL query must contain a pipe-delimited operator."})
        elif not lowered.split("|", 1)[0].strip():
            errors.append({"code": "KQL_SOURCE", "message": "KQL must begin with a table or tabular expression."})
        warnings.append({"code": "KQL_STATIC_ONLY", "message": "KQL syntax and table/column availability require validation in the target Sentinel workspace."})
    elif platform is TargetPlatform.CHRONICLE:
        if not all(section in lowered for section in ("rule ", "events:", "condition:")):
            errors.append({"code": "YARAL_STRUCTURE", "message": "YARA-L 2.0 candidate must include rule, events, and condition sections."})
        warnings.append({"code": "YARAL_STATIC_ONLY", "message": "YARA-L compilation, UDM field compatibility and outcome semantics require Chronicle validation."})
    elif platform is TargetPlatform.CROWDSTRIKE:
        warnings.append({"code": "FALCON_VALIDATION_PENDING", "message": "CrowdStrike query grammar validation is not enabled until the current NG-SIEM contract is verified."})

    return {
        "status": "failed" if errors else "passed_with_warnings" if warnings else "passed",
        "errors": errors,
        "warnings": warnings,
        "checks_performed": ["non_empty", "null_byte", "markdown_fence", "placeholder", "balanced_delimiters", f"{platform.value}_structure"],
        "is_deployable": False,
    }
