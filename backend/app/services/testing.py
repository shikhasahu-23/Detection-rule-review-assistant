"""Offline query-contract checks; this module never executes SIEM queries."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.schemas.testing import DetectionTestSuite


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def run_query_contract_suite(query: str, suite: DetectionTestSuite) -> dict:
    """Check explicit query-text assertions against a candidate version.

    Fixture payloads are retained as scenario context, but are not sent to a SIEM
    and are not evaluated as runtime events.
    """
    normalized = query.casefold()
    results: list[dict] = []
    for case in suite.cases:
        checks = []
        for assertion in case.assertions:
            term = assertion.value.casefold()
            pattern = rf"(?<![a-zA-Z0-9_]){re.escape(term)}(?![a-zA-Z0-9_])"
            found = re.search(pattern, normalized) is not None
            passed = found if assertion.operator == "contains" else not found
            checks.append({
                "operator": assertion.operator,
                "value": assertion.value,
                "passed": passed,
            })
        results.append({
            "name": case.name,
            "scenario_type": case.scenario_type,
            "fixture": case.fixture,
            "status": "passed" if all(item["passed"] for item in checks) else "failed",
            "checks": checks,
        })
    passed = sum(item["status"] == "passed" for item in results)
    suite_payload = suite.model_dump(mode="json")
    return {
        "suite_fingerprint": _fingerprint(suite_payload),
        "query_fingerprint": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "total_cases": len(results),
        "passed_cases": passed,
        "failed_cases": len(results) - passed,
        "status": "passed" if passed == len(results) else "failed",
        "case_results": results,
    }


def compare_regression(current: dict, previous: dict | None) -> dict:
    if previous is None:
        return {"status": "baseline", "regressions": [], "improvements": []}
    old = {item["name"]: item["status"] for item in previous.get("case_results", [])}
    new = {item["name"]: item["status"] for item in current["case_results"]}
    regressions = sorted(name for name, status in old.items() if status == "passed" and new.get(name) == "failed")
    improvements = sorted(name for name, status in new.items() if status == "passed" and old.get(name) == "failed")
    return {
        "status": "regressed" if regressions else "improved" if improvements else "unchanged",
        "regressions": regressions,
        "improvements": improvements,
    }
