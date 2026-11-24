"""Deterministic telemetry coverage scoring for generated query drafts."""
from __future__ import annotations

import re


def score_telemetry_coverage(intent: dict, query: str) -> dict:
    """Score required fields as whole tokens; this does not verify real schemas."""
    lowered = query.lower()
    requirements: list[dict] = []
    for item in intent.get("required_telemetry") or []:
        source = str(item.get("source", "")).strip()
        fields = [str(value).strip() for value in item.get("required_fields", []) if str(value).strip()]
        for field in fields or ([source] if source else []):
            pattern = rf"(?<![a-zA-Z0-9_]){re.escape(field.lower())}(?![a-zA-Z0-9_])"
            requirements.append({
                "source": source,
                "field": field if fields else None,
                "present": re.search(pattern, lowered) is not None,
            })
    total = len(requirements)
    matched = sum(1 for item in requirements if item["present"])
    score = round(matched / total * 100) if total else None
    return {
        "score": score,
        "status": "not_assessed" if score is None else "high" if score >= 80 else "moderate" if score >= 50 else "low",
        "matched_requirements": matched,
        "total_requirements": total,
        "requirements": requirements,
        "method": "case-insensitive whole-token matching; lexical hint only, not schema verification",
    }
