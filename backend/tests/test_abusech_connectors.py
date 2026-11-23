import httpx
import pytest

from app.intel.connectors.threatfox import THREATFOX_API_URL, ThreatFoxConnector
from app.intel.connectors.urlhaus import URLHAUS_RECENT_URLS_API, UrlhausConnector
from app.intel.schemas import IndicatorType


@pytest.mark.asyncio
async def test_urlhaus_fetch_parse_and_health():
    payload = {
        "query_status": "ok",
        "urls": [
            {
                "id": "123",
                "url": "https://malware.example/payload.exe",
                "date_added": "2026-11-22 10:00:00",
                "url_status": "online",
                "threat": "malware_download",
            }
        ],
    }

    async def handler(request):
        assert str(request.url) == URLHAUS_RECENT_URLS_API
        assert request.headers["Auth-Key"] == "urlhaus-test"
        assert request.content == b"limit=25"
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        connector = UrlhausConnector(client)
        await connector.configure({"auth_key": "urlhaus-test", "limit": 25})
        records = [record async for record in connector.fetch()]

    indicator = connector.parse(records[0])[0]
    assert indicator.indicator_type == IndicatorType.URL
    assert indicator.value == "https://malware.example/payload.exe"
    assert indicator.evidence[0].source_reference == "https://urlhaus.abuse.ch/url/123/"
    assert (await connector.health()).status.value == "healthy"


@pytest.mark.asyncio
async def test_urlhaus_requires_auth_key_and_rejects_bad_limit():
    connector = UrlhausConnector()
    with pytest.raises(ValueError, match="auth_key"):
        await connector.configure({})
    with pytest.raises(ValueError, match="limit"):
        await connector.configure({"auth_key": "test", "limit": 1001})


@pytest.mark.asyncio
async def test_threatfox_fetch_parse_and_checkpoint():
    payload = {
        "query_status": "ok",
        "data": [
            {
                "id": "42",
                "ioc": "bad.example",
                "ioc_type": "domain",
                "confidence_level": 95,
                "first_seen": "2026-11-20 12:00:00",
                "last_seen": "2026-11-22 12:00:00",
            }
        ],
    }

    async def handler(request):
        assert str(request.url) == THREATFOX_API_URL
        assert request.headers["Auth-Key"] == "threatfox-test"
        assert request.read() == b'{"query":"get_iocs","days":2}'
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        connector = ThreatFoxConnector(client)
        await connector.configure({"auth_key": "threatfox-test", "days": 2})
        records = [record async for record in connector.fetch()]

    indicator = connector.parse(records[0])[0]
    assert indicator.indicator_type == IndicatorType.DOMAIN
    assert indicator.value == "bad.example"
    assert indicator.confidence == 95
    assert indicator.evidence[0].source_reference == "https://threatfox.abuse.ch/ioc/42/"
    assert (await connector.health()).status.value == "healthy"


@pytest.mark.asyncio
async def test_threatfox_skips_unsupported_composite_ioc_type():
    connector = ThreatFoxConnector()
    parsed = connector.parse({"ioc": "192.0.2.10:443", "ioc_type": "ip:port"})
    assert parsed == []


@pytest.mark.asyncio
async def test_threatfox_rejects_invalid_days():
    connector = ThreatFoxConnector()
    with pytest.raises(ValueError, match="days"):
        await connector.configure({"auth_key": "test", "days": 8})
