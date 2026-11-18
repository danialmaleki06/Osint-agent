import asyncio
from datetime import timedelta

import httpx
import pytest
import respx

from osint_mcp import server
from osint_mcp.context import sanctions
from osint_mcp.tools.quarantine import QuarantineStore

SOURCE = "international_sanctions"
MATCH = "7708619320"
ABSENT = "7724744134"
OFAC_XML = f"""<sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML">
 <publshInformation><Publish_Date>11/18/2026</Publish_Date><Record_Count>1</Record_Count></publshInformation>
 <sdnEntry><uid>123</uid><lastName>Listed Test Company</lastName><idList>
  <id><idType>Tax ID No.</idType><idCountry>Russia</idCountry><idNumber>{MATCH}</idNumber></id>
  <id><idType>Registration Number</idType><idCountry>Russia</idCountry><idNumber>{ABSENT}</idNumber></id>
 </idList></sdnEntry>
</sdnList>"""
EU_XML = f"""<export xmlns="http://eu.europa.ec/fpi/fsd/export" generationDate="2026-11-18T12:00:00+00:00">
 <sanctionEntity logicalId="456" euReferenceNumber="EU.123.45">
  <nameAlias wholeName="Listed Test Company"/>
  <identification identificationTypeCode="fiscalcode" countryIso2Code="RU" number="{MATCH}"/>
  <identification identificationTypeCode="taxid" countryIso2Code="RU" number="{ABSENT}" knownFalse="true"/>
 </sanctionEntity>
</export>"""


@pytest.fixture
def services(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_sanctions_registry", sanctions.SanctionsRegistry())
    store = QuarantineStore(tmp_path / "q.db")
    monkeypatch.setattr(server, "_quarantine", store)
    yield store
    store.close()


def _feeds():
    return [respx.get(url).mock(return_value=httpx.Response(
        200, text=EU_XML if tag.startswith("EU ") else OFAC_XML,
    )) for tag, url in sanctions._FEEDS.items()]


@respx.mock
async def test_single_and_batch_share_official_downloads_and_exact_match(services):
    routes = _feeds()
    batch, single = await asyncio.gather(
        server.scan_catalog_batch(SOURCE, [ABSENT, MATCH, MATCH, "123"]),
        server.scan_catalog_source(MATCH, SOURCE),
    )

    assert [route.call_count for route in routes] == [1, 1, 1]
    assert batch["status"] == "partial" and batch["total_checked"] == 2
    assert batch["details"]["123"]["status"] == "invalid_inn"
    assert batch["details"][ABSENT]["status"] == "not_found"
    assert single.status == "ok" and single.found == batch["details"][MATCH]["hits_count"] == 3
    assert single.datasets == batch["datasets"]
    assert {f.payload["dataset"] for f in single.hits} == set(sanctions._FEEDS)
    assert all(f.payload["matched_inn"] == MATCH for f in services.list_pending(MATCH))
    assert not services.list_pending(ABSENT)


@respx.mock
async def test_unavailable_mandatory_feed_cannot_produce_negative_or_stale_result(services, monkeypatch):
    routes = _feeds()
    assert (await server.scan_catalog_source(MATCH, SOURCE)).status == "ok"
    monkeypatch.setattr(sanctions, "_TTL", timedelta(0))
    routes[-1].mock(return_value=httpx.Response(503))

    single = await server.scan_catalog_source(ABSENT, SOURCE)
    assert single.status == "unavailable" and "EU Financial Sanctions: HTTP 503" in single.note
    batch = await server.scan_catalog_batch(SOURCE, [MATCH, ABSENT])
    assert batch["status"] == "unavailable" and batch["total_checked"] == 0
    assert {row["status"] for row in batch["details"].values()} == {"unavailable"}


@respx.mock
async def test_200_with_wrong_export_is_unavailable(services):
    routes = _feeds()
    routes[0].mock(return_value=httpx.Response(200, text=OFAC_XML.replace("<Record_Count>1", "<Record_Count>2")))

    result = await server.scan_catalog_source(MATCH, SOURCE)

    assert result.status == "unavailable" and "OFAC SDN" in result.note
    assert not services.list_pending(MATCH)
