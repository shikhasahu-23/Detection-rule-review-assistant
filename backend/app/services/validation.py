"""Conservative static checks for candidate query text."""
import yaml

from app.schemas.detection import TargetPlatform
from app.services.coverage import score_telemetry_coverage


def _balanced_delimiters(query: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    for char in query:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}" and (not stack or stack.pop() != pairs[char]):
            return False
    return not stack and quote is None


def validate_candidate(platform: TargetPlatform, query: str, intent: dict | None = None) -> dict:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    normalized = query.strip()
    lowered = normalized.lower()
    if not normalized:
        errors.append({"code": "EMPTY_QUERY", "message": "Query cannot be empty."})
    if "\\x00" in normalized:
        errors.append({"code": "NULL_BYTE", "message": "Query contains a null byte."})
    if normalized.startswith("\\x60\\x60\\x60") or normalized.endswith("\\x60\\x60\\x60"):
        errors.append({"code": "MARKDOWN_FENCE", "message": "Remove Markdown fences; store only the native query."})
    if any(token in lowered for token in ("<insert ", "todo:", "your query here", "replace_me")):
        errors.append({"code": "PLACEHOLDER", "message": "Query contains an unresolved placeholder."})
    if normalized and not _balanced_delimiters(normalized):
        errors.append({"code": "UNBALANCED_DELIMITERS", "message": "Query contains unbalanced quotes or delimiters."})
    if platform is TargetPlatform.SPLUNK:
        if not lowered.startswith(("search ", "|", "tstats ", "from ", "index=")):
            errors.append({"code": "SPL_ENTRYPOINT", "message": "Expected a Splunk search pipeline entrypoint."})
        warnings.append({"code": "SPL_STATIC_ONLY", "message": "SPL macros, data models and field availability require validation in a representative Splunk environment."})
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
    elif platform is TargetPlatform.SIGMA:
        try:
            if yaml is None:
                raise ValueError("PyYAML dependency is not installed")
            document = yaml.safe_load(normalized)
            if not isinstance(document, dict):
                raise ValueError("Sigma document must be a YAML mapping")
            required = {"title", "id", "logsource", "detection", "level"}
            missing = sorted(required - set(document))
            if missing:
                errors.append({"code": "SIGMA_REQUIRED_FIELDS", "message": "Missing Sigma fields: " + ", ".join(missing)})
            if not isinstance(document.get("detection"), dict) or "condition" not in document.get("detection", {}):
                errors.append({"code": "SIGMA_DETECTION", "message": "Sigma detection must be a mapping with a condition."})
            warnings.append({"code": "SIGMA_BACKEND_MAPPING", "message": "YAML is parsed; validate field names and backend compatibility with the target Sigma pipeline."})
        except Exception as exc:
            errors.append({"code": "SIGMA_YAML", "message": f"Invalid Sigma YAML: {str(exc)[:200]}"})
    elif platform is TargetPlatform.CROWDSTRIKE:
        warnings.append({"code": "FALCON_VALIDATION_PENDING", "message": "CrowdStrike query grammar validation is not enabled until the current NG-SIEM contract is verified."})
    coverage = score_telemetry_coverage(intent or {}, normalized)
    if coverage["status"] == "low":
        warnings.append({"code": "LOW_TELEMETRY_COVERAGE", "message": "The candidate includes fewer than half of the explicitly required telemetry fields."})
    elif coverage["status"] == "moderate":
        warnings.append({"code": "PARTIAL_TELEMETRY_COVERAGE", "message": "The candidate includes only some explicitly required telemetry fields."})
    return {
        "status": "failed" if errors else "passed_with_warnings" if warnings else "passed",
        "errors": errors,
        "warnings": warnings,
        "checks_performed": ["non_empty", "null_byte", "markdown_fence", "placeholder", "balanced_delimiters", f"{platform.value}_structure"],
        "telemetry_coverage": coverage,
        "is_deployable": False,
    }
