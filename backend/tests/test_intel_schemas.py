from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.intel.schemas import IndicatorType, IntelIndicatorInput


def evidence():
    return {
        "source_name": "test-feed",
        "payload_hash": "a" * 64,
        "raw_payload": {"id": "sample-1"},
    }


@pytest.mark.parametrize(
    ("indicator_type", "value", "expected"),
    [
        (IndicatorType.IP_ADDRESS, "2001:0DB8::1", "2001:db8::1"),
        (IndicatorType.DOMAIN, "Example.COM.", "example.com"),
        (IndicatorType.URL, "HTTPS://Example.COM/path#fragment", "https://example.com/path"),
        (IndicatorType.SHA256, "A" * 64, "a" * 64),
        (IndicatorType.CVE, "cve-2025-1234", "CVE-2025-1234"),
        (IndicatorType.EMAIL, "Analyst@Example.COM", "analyst@example.com"),
    ],
)
def test_indicator_values_are_normalized(indicator_type, value, expected):
    indicator = IntelIndicatorInput(
        indicator_type=indicator_type,
        value=value,
        evidence=[evidence()],
    )

    assert indicator.value == expected


def test_confidence_must_be_between_zero_and_one_hundred():
    with pytest.raises(ValidationError):
        IntelIndicatorInput(
            indicator_type=IndicatorType.DOMAIN,
            value="example.com",
            confidence=101,
            evidence=[evidence()],
        )


def test_indicator_requires_source_evidence():
    with pytest.raises(ValidationError):
        IntelIndicatorInput(
            indicator_type=IndicatorType.DOMAIN,
            value="example.com",
            evidence=[],
        )


def test_first_seen_cannot_follow_last_seen():
    with pytest.raises(ValidationError, match="first_seen_at"):
        IntelIndicatorInput(
            indicator_type=IndicatorType.DOMAIN,
            value="example.com",
            first_seen_at=datetime(2026, 2, 2, tzinfo=UTC),
            last_seen_at=datetime(2026, 2, 1, tzinfo=UTC),
            evidence=[evidence()],
        )


def test_invalid_url_is_rejected():
    with pytest.raises(ValidationError):
        IntelIndicatorInput(
            indicator_type=IndicatorType.URL,
            value="javascript:alert(1)",
            evidence=[evidence()],
        )
