from osint_mcp.models import CompanyContext
from osint_mcp.tools.affiliations_lite import build_affiliations_lite


def test_build_affiliations_lite_with_card():
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"',
        director_fio="Иванов Иван Иванович",
        director_post="Генеральный директор",
    )
    card = {
        "Руковод": {"ФИО": "Иванов Иван Иванович", "Должн": "Генеральный директор"},
        "Учредители": [
            {
                "Наим": "ООО «ЛАНИТ ВЕНЧУРС»",
                "ИНН": "7701234567",
                "ОГРН": "1027700123456",
                "Процент": 100.0,
            }
        ],
        "ДочернОрг": [
            {"Наим": "ООО «БПМ РАЗРАБОТКА»", "ИНН": "7724999999"}
        ]
    }
    res = build_affiliations_lite(ctx, card)
    assert res is not None
    assert "Холдинговая структура" in res["тип_контроля"]
    assert res["материнская_компания"]["наименование"] == "ООО «ЛАНИТ ВЕНЧУРС»"
    assert res["руководитель"]["фио"] == "Иванов Иван Иванович"
    assert len(res["дочерние_организации"]) == 1


def test_build_affiliations_lite_ao_undisclosed():
    ctx = CompanyContext(
        inn="7718668887",
        name_legal='АКЦИОНЕРНОЕ ОБЩЕСТВО "ПОЗИТИВ ТЕКНОЛОДЖИЗ"',
    )
    card = {"ДержРеестрАО": "АО РТ-Регистратор"}
    res = build_affiliations_lite(ctx, card)
    assert res is not None
    assert "реестр акционеров закрыт" in res["тип_контроля"]
