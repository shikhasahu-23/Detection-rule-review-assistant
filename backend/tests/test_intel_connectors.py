import httpx
import pytest

from app.intel.connectors.cisa_kev import CISA_KEV_URL, CisaKevConnector
from app.intel.connectors.nvd import NVD_API_URL, NvdConnector
from app.intel.schemas import IndicatorType


@pytest.mark.asyncio
async def test_cisa_kev_fetch_parse_and_checkpoint():
    payload = {
        "catalogVersion": "2026.11.20",
        "dateReleased": "2026-11-20T12:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-1234",
                "dateAdded": "2026-11-19",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }

    async def handler(request):
        assert str(request.url) == CISA_KEV_URL
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        connector = CisaKevConnector(client)
        await connector.configure({})
        records = [record async for record in connector.fetch()]

    parsed = connector.parse(records[0])
    assert parsed[0].indicator_type == IndicatorType.CVE
    assert parsed[0].value == "CVE-2025-1234"
    assert parsed[0].severity == "critical"
    assert connector.get_checkpoint() == {"catalog_version": "2026.11.20"}
    assert (await connector.health()).status.value == "healthy"


@pytest.mark.asyncio
async def test_cisa_kev_skips_catalog_matching_checkpoint():
    async def handler(request):
        return httpx.Response(
            200,
            json={"catalogVersion": "v1", "vulnerabilities": [{"cveID": "CVE-2025-1234"}]},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        connector = CisaKevConnector(client)
        records = [record async for record in connector.fetch({"catalog_version": "v1"})]

    assert records == []


@pytest.mark.asyncio
async def test_nvd_fetch_paginates_and_parse():
    pages = {
        0: {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2025-1111", "published": "2025-01-01T00:00:00.000Z"}}
            ],
        },
        1: {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2025-2222", "published": "2025-02-01T00:00:00.000Z"}}
            ],
        },
    }

    async def handler(request):
        assert request.url.host == "services.nvd.nist.gov"
        start = int(request.url.params["startIndex"])
        assert request.url.params["resultsPerPage"] == "1"
        return httpx.Response(200, json=pages[start])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        connector = NvdConnector(client)
        await connector.configure({"results_per_page": 1, "api_key": "test-key"})
        records = [record async for record in connector.fetch()]

    assert len(records) == 2
    assert connector.parse(records[0])[0].value == "CVE-2025-1111"
    assert connector.get_checkpoint() == {"start_index": "2", "total_results": "2"}


@pytest.mark.asyncio
async def test_nvd_rejects_unsupported_config():
    connector = NvdConnector()
    with pytest.raises(ValueError, match="Unsupported"):
        await connector.configure({"endpoint": "https://example.invalid"})


@pytest.mark.asyncio
async def test_nvd_rejects_invalid_page_size():
    connector = NvdConnector()
    with pytest.raises(ValueError, match="results_per_page"):
        await connector.configure({"results_per_page": 2001})
