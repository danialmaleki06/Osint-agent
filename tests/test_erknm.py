from datetime import UTC, datetime, timedelta
from io import BytesIO
from zipfile import ZipFile

import httpx
import pytest
import respx

from osint_mcp import server
from osint_mcp.context import erknm
from osint_mcp.tools.quarantine import QuarantineStore

INN = "7724744134"
OTHER = "7708619320"


def _archive(period, monthly, empty_file=False):
    year, _, month = period.partition("-")
    ns = "https://proverki.gov.ru/opendata/3.0/"
    inspection_ns = ns + "20220115"
    root_ns = ns + ("20220125" if monthly else "20220115")
    root = "INSPECTIONS" if monthly else "PLAN"
    xml = f'''<r:{root} xmlns:r="{root_ns}" xmlns="{inspection_ns}" YEAR="{year}" MONTH="{month}">
      <INSPECTION ERPID="1234" STATUS="Завершено" TYPE_NAME="Плановое КНМ">
        <SUBJECT INN="{INN}"/><KNO_ORGANIZATION VALUE="Управление Роспотребнадзора"/>
      </INSPECTION>
      <INSPECTION ERPID="2345" STATUS="Запланировано">
        <SUBJECT INN="{OTHER}"/><KNO_ORGANIZATION VALUE="Роструд"/>
      </INSPECTION>
    </r:{root}>'''
    result = BytesIO()
    with ZipFile(result, "w") as archive:
        archive.writestr("data.xml", xml)
        if empty_file:
            archive.writestr("empty.xml", "")
    return result.getvalue()


@pytest.mark.parametrize("monthly,empty_file", [(False, False), (True, False), (False, True)])
@respx.mock
async def test_erknm_scans_exact_inn_in_shared_official_archive(monkeypatch, tmp_path, monthly, empty_file):
    registry = erknm.ErknmRegistry(monthly=monthly)
    store = QuarantineStore(tmp_path / "q.db")
    monkeypatch.setattr(server, "_quarantine", store)
    monkeypatch.setattr(server, "_erknm_month" if monthly else "_erknm_plan", registry)
    source = "rospotrebnadzor_inspections" if monthly else "rospotrebnadzor_plan"
    today = datetime.now(UTC) + timedelta(hours=3)
    period = today.strftime("%Y-%m" if monthly else "%Y")
    endpoint = f"{today.year}/{today.month}" if monthly else f"plans/{today.year}"
    path = "erknm-opendata" if monthly else "erknm-plan"
    url = f"https://proverki.gov.ru/blob/{path}/data.zip"
    query = {"isFederalLaw248": "true"}
    respx.get(erknm._API + endpoint, params=query).respond(
        json={"dataZipUrl": url, "history": [{"fileUrl": url, "published": today.date().isoformat()}]},
    )
    archive = respx.get(url).respond(content=_archive(period, monthly, empty_file))

    try:
        batch = await server.scan_catalog_batch(source, [INN, OTHER])
        single = await server.scan_catalog_source(INN, source)
        assert batch["status"] == single.status == ("partial" if empty_file else "ok")
        assert batch["details"][INN]["hits_count"] == single.found == 1
        assert batch["details"][OTHER]["status"] == (
            "not_found_in_available_records" if empty_file else "not_found"
        )
        assert single.hits[0].payload["number"] == "1234"
        assert single.hits[0].payload["status"] == "Завершено"
        assert archive.call_count == 1
    finally:
        store.close()


@respx.mock
async def test_erknm_unavailable_is_not_an_empty_lookup(monkeypatch):
    monkeypatch.setattr(server, "_erknm_plan", erknm.ErknmRegistry())
    today = datetime.now(UTC) + timedelta(hours=3)
    respx.get(erknm._API + f"plans/{today.year}", params={"isFederalLaw248": "true"}).respond(503)

    reply = await server.scan_catalog_source(INN, "rospotrebnadzor_plan")

    assert reply.status == "unavailable"
    assert "HTTP 503" in reply.note
