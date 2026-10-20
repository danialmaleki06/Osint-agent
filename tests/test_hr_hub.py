import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.models import CompanyContext, HiringInfo
from osint_mcp.tools.hr_hub import detect_corporate_hr_hub


@respx.mock
async def test_detect_corporate_hr_hub_found():
    ctx = CompanyContext(
        inn="7743001840",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "ВК"',
        name_short='ООО "ВК"',
        brand="VK",
        size_category="large",
        revenue_latest=10_000_000_000.0,
        hiring=HiringInfo(open_vacancies=0),
    )

    respx.get(f"{settings.hh_base_url}/employers", params={"text": "VK", "per_page": "20"}).mock(
        return_value=httpx.Response(200, json={
            "found": 1,
            "items": [{"id": "15478", "name": "VK", "open_vacancies": 159}]
        })
    )

    res = await detect_corporate_hr_hub(ctx)
    assert res is not None
    assert res["обнаружен"] is True
    assert res["employer_id"] == "15478"
    assert res["вакансий_в_хабе"] == 159
    assert "централизованном HR-хабе" in res["пояснение"]


@respx.mock
async def test_detect_corporate_hr_hub_skipped_if_vacancies_exist():
    ctx = CompanyContext(
        inn="7724744134",
        name_legal="ООО БПМСОФТ",
        brand="BPMSOFT",
        hiring=HiringInfo(open_vacancies=15),
    )
    res = await detect_corporate_hr_hub(ctx)
    assert res is None
