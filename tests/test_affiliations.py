"""Тесты обхода связей.

Каждый тест здесь закрывает конкретную дыру, найденную на живых данных
БПМСофт. Формулировки в assert намеренно проверяют смысл, а не форму:
важно не то, какое поле заполнено, а то, что читатель отчёта не примет
непроверенное за благополучное.
"""

import json
from copy import deepcopy
from pathlib import Path

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource

pytestmark = pytest.mark.anyio

FIXTURES = Path(__file__).parent / "fixtures"
BPMSOFT = "7724744134"
LANSOFT = "9717157227"      # владелец 78,8% — АО, акционеры не раскрыты
CARD = f"{settings.checko_base_url}/company"
PERSON = f"{settings.checko_base_url}/person"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_key", "test-key")


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _wrap(data: dict) -> dict:
    return {"meta": {"status": "ok"}, "data": data}


def _blank(**over) -> dict:
    """Пустая карточка организации: только то, что переопределено."""
    base = {"ИНН": "0000000000", "ОГРН": "0", "НаимСокр": "ООО «Пусто»",
            "Статус": {"Наим": "Действует"}, "Руковод": [], "Учред": {},
            "ЕФРСБ": [], "Правопредш": [], "Правопреем": [], "СвязУчред": []}
    base.update(over)
    return base


def _mock_cards(target: dict, default: dict | None = None, inn: str = BPMSOFT) -> None:
    """Карточка проверяемой организации — одна, всем прочим отдаём default.

    Триаж обращается к тому же методу, что и карточка цели, поэтому
    различать приходится по параметрам запроса.
    """
    respx.get(CARD, params__contains={"inn": inn}).mock(
        return_value=httpx.Response(200, json=_wrap(target)))
    respx.get(CARD).mock(
        return_value=httpx.Response(200, json=_wrap(default or _blank())))


def _mock_person(data: dict | None = None) -> None:
    person = _fixture("checko_person_director.json")
    if data:
        person["data"].update(data)
    respx.get(PERSON).mock(return_value=httpx.Response(200, json=person))


# ─────────────────  владелец-организация  ─────────────────

@respx.mock
async def test_organization_owner_is_not_lost():
    """Владелец 78,8% — юрлицо, и раньше он выпадал целиком.

    Код обходил только Учред.ФЛ. У БПМСофт это трое физлиц с долями
    5,6 / 5,6 / 10 процентов, а контрольный пакет держит АО «ЛАНСОФТ»,
    которого проверка не видела вовсе.
    """
    _mock_cards(_fixture("checko_company_bpmsoft.json")["data"])
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    owners = {o.name for o in graph.owner_organizations}
    assert any("ЛАНСОФТ" in (n or "") for n in owners), \
        f"владелец контрольного пакета потерян, найдено: {owners}"


@respx.mock
async def test_owner_share_is_kept():
    """5,6% и 78,8% нельзя подавать одинаково."""
    _mock_cards(_fixture("checko_company_bpmsoft.json")["data"])
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)
    shares = [p.share_percent for p in graph.people if p.share_percent]
    assert shares, "доли учредителей отброшены"


# ─────────────────  акционерное общество  ─────────────────

@respx.mock
async def test_undisclosed_shareholders_are_declared():
    """У АО акционеры в реестре не раскрыты — это стена, а не чистота.

    Прежний код на пустой Учред отвечал «не указаны физические лица»,
    и отчёт читался как «собственников нет».
    """
    _mock_cards(_blank(ДержРеестрАО={"Наим": "АО «Регистратор»"}), inn=LANSOFT)

    graph, _ = await CheckoSource().check_affiliations(LANSOFT, deep=False)

    assert graph.shareholders_undisclosed is True
    assert "НЕ РАСКРЫВАЕТСЯ" in graph.coverage_note


# ─────────────────  реорганизация  ─────────────────

@respx.mock
async def test_predecessor_is_found():
    """Смена юрлица даёт новый ИНН — связь видна только через правопреемство."""
    _mock_cards(_blank(Правопредш=[{
        "ИНН": "7700000001", "ОГРН": "1", "НаимСокр": 'ООО "Прошлое"',
        "Статус": "Ликвидировано", "ДатаРег": "2015-01-01"}]))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert len(graph.predecessors) == 1
    assert graph.predecessors[0].name == 'ООО "Прошлое"'
    assert graph.predecessors[0].link == "правопредшественник"


# ─────────────────  триаж связанных  ─────────────────

@respx.mock
async def test_liquidated_related_company_is_suspicious():
    """Брошенное юрлицо владельца — главный признак, ради которого всё затеяно."""
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000002", "ОГРН": "2",
                           "НаимСокр": 'ООО "Брошенное"'}]),
        default=_blank(ИНН="7700000002", НаимСокр='ООО "Брошенное"',
                       Статус={"Наим": "Исключено из ЕГРЮЛ"}),
    )

    graph, res = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    rc = graph.related_companies[0]
    assert rc.suspicious is True
    assert rc.status == "Исключено из ЕГРЮЛ"
    assert graph.suspicious_count == 1
    # и это обязано стать фактом со ссылкой, а не остаться в структуре
    assert any("Брошенное" in f.statement for f in res.facts)


@respx.mock
async def test_related_company_carries_name_not_bare_inn():
    """Голый ИНН в отчёте бесполезен: читатель не поймёт, что перед ним."""
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000003", "ОГРН": "3",
                           "НаимСокр": 'ООО "Ромашка"', "Статус": "Действует",
                           "ДатаРег": "2019-05-05"}]),
    )

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    rc = graph.related_companies[0]
    assert rc.name == 'ООО "Ромашка"'
    assert rc.status == "Действует"
    assert str(rc.registered_at) == "2019-05-05"
    assert rc.source_url.startswith("http")


@respx.mock
async def test_flagged_related_company_is_suspicious():
    """Действующая, но с поднятой отметкой — тоже подозрительна."""
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000004", "ОГРН": "4",
                           "НаимСокр": 'ООО "С отметкой"'}]),
        default=_blank(ИНН="7700000004", Санкции=True, НедобПост=True),
    )

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    rc = graph.related_companies[0]
    assert rc.suspicious is True
    assert len(rc.flags) == 2


@respx.mock
async def test_unavailable_triage_is_not_clean():
    """Неответивший источник обязан отличаться от «проверено, чисто»."""
    respx.get(CARD, params__contains={"inn": BPMSOFT}).mock(
        return_value=httpx.Response(200, json=_wrap(
            _blank(СвязУчред=[{"ИНН": "7700000005", "ОГРН": "5"}]))))
    respx.get(CARD).mock(return_value=httpx.Response(503))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    rc = graph.related_companies[0]
    assert rc.triage_status == "unavailable"
    assert rc.suspicious is False          # не выдумываем риск
    assert "НЕ ПРОВЕРЕНЫ" in graph.coverage_note


# ─────────────────  люди  ─────────────────

@respx.mock
async def test_person_without_inn_does_not_vanish():
    """Раньше такой человек исчезал молча — как будто его не существует."""
    _mock_cards(_blank(Руковод=[{"ФИО": "Безномеров Б. Б.",
                                 "НаимДолжн": "ДИРЕКТОР"}]))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert len(graph.people) == 1
    p = graph.people[0]
    assert p.fio == "Безномеров Б. Б."
    assert p.checked is False
    assert "ИНН" in p.not_checked_reason
    assert "проверить невозможно" in graph.coverage_note


@respx.mock
async def test_unreliable_and_disqualified_are_read():
    """Две отметки, которые есть только в карточке и раньше терялись."""
    _mock_cards(_blank(Руковод=[{"ФИО": "Иванов И. И.", "ИНН": "500100732259",
                                 "НаимДолжн": "ДИРЕКТОР", "Недост": True,
                                 "ДисквЛицо": True}]))
    _mock_person()

    graph, res = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    p = graph.people[0]
    assert p.unreliable is True
    assert p.disqualified is True
    texts = " ".join(f.statement for f in res.facts)
    assert "недостоверными" in texts
    assert "дисквалифицирован" in texts


@respx.mock
async def test_roles_are_merged_for_one_person():
    """Директор и учредитель в одном лице — одна запись, обе роли."""
    card = _blank(
        Руковод=[{"ФИО": "Директоров Д. П.", "ИНН": "770000000156",
                  "НаимДолжн": "ГЕНЕРАЛЬНЫЙ ДИРЕКТОР"}],
        Учред={"ФЛ": [{"ФИО": "Директоров Д. П.", "ИНН": "770000000156",
                       "Доля": {"Процент": 10.0}}]},
    )
    _mock_cards(card)
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert len(graph.people) == 1, "человек задвоился"
    assert "учредитель" in graph.people[0].role_in_company
    assert graph.people[0].share_percent == 10.0


@respx.mock
async def test_person_source_failure_is_visible():
    """Отказ по человеку — не «рисков нет»."""
    _mock_cards(_blank(Руковод=[{"ФИО": "Иванов И. И.", "ИНН": "500100732259",
                                 "НаимДолжн": "ДИРЕКТОР"}]))
    respx.get(PERSON).mock(return_value=httpx.Response(500))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.people[0].checked is False
    assert graph.people[0].not_checked_reason


# ─────────────────  лимиты  ─────────────────

@respx.mock
async def test_people_limit_is_declared(monkeypatch):
    """Молча обрезанный граф выглядит как полный — так нельзя."""
    monkeypatch.setattr(settings, "affiliation_max_people", 2)
    _mock_cards(_blank(Учред={"ФЛ": [
        {"ФИО": f"Лицо {i}", "ИНН": f"50010073225{i}"} for i in range(5)]}))
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert len(graph.people) == 2
    assert "лимит" in graph.coverage_note
    assert "НЕ ПРОВЕРЕНЫ" in graph.coverage_note


@respx.mock
async def test_related_limit_is_declared(monkeypatch):
    monkeypatch.setattr(settings, "affiliation_max_related", 2)
    _mock_cards(_blank(СвязУчред=[
        {"ИНН": f"770000000{i}", "ОГРН": str(i)} for i in range(5)]))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    checked = [rc for rc in graph.related_companies if rc.triage_status != "not_checked"]
    assert len(checked) == 2
    assert "лимит" in graph.coverage_note


# ─────────────────  глубокая проверка  ─────────────────

@respx.mock
async def test_deep_check_runs_only_on_suspicious():
    """Полная проверка стоит дорого — она не должна идти по всем подряд."""
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000006", "ОГРН": "6",
                           "НаимСокр": 'ООО "Чистое"', "Статус": "Действует"}]),
        default=_blank(ИНН="7700000006", Статус={"Наим": "Действует"}),
    )
    cases = respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap({"Записи": []})))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    assert graph.related_companies[0].suspicious is False
    assert not cases.called, "глубокая проверка ушла на благополучную организацию"


@respx.mock
async def test_deep_summary_reaches_the_fact():
    """Итог глубокой проверки обязан попасть в текст факта, а не осесть внутри."""
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000007", "ОГРН": "7",
                           "НаимСокр": 'ООО "Плохое"'}]),
        default=_blank(ИНН="7700000007", Статус={"Наим": "Ликвидировано"}),
    )
    case = {"Номер": "А40-1/2020", "Дата": "2020-01-01", "СуммИск": 45_000_000,
            "Ответ": [{"ИНН": "7700000007"}], "Ист": [], "Суд": "АС Москвы",
            "СтрКАД": "https://kad.arbitr.ru/card/1"}
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [case], "ЗапВсего": 1, "СтрВсего": 1})))
    respx.get(f"{settings.checko_base_url}/enforcements").mock(
        return_value=httpx.Response(200, json=_wrap({"Записи": [], "ОбщКолич": 0})))
    respx.get(f"{settings.checko_base_url}/inspections").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))

    graph, res = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    rc = graph.related_companies[0]
    assert rc.deep_summary and "ответчик" in rc.deep_summary
    texts = " ".join(f.statement for f in res.facts)
    assert "Плохое" in texts and "ответчик" in texts


@respx.mock
async def test_target_company_is_never_its_own_relative():
    """Компания не может быть связана сама с собой — иначе отчёт абсурден."""
    _mock_cards(_blank(СвязУчред=[{"ИНН": BPMSOFT, "ОГРН": "1107746293049"}]))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.related_companies == []


@respx.mock
async def test_self_reference_by_ogrn_is_dropped():
    """Связь приходит одним ОГРН, и ИНН выясняется только после триажа.

    Именно так проверяемая организация попадала в список связанных
    сама с собой: на момент добавления её ИНН был неизвестен.
    Поймано на живом прогоне, тест выше эту ветку не закрывал.
    """
    _mock_cards(
        _blank(СвязУпрОрг=["1107746293049"]),
        default=_blank(ИНН=BPMSOFT, НаимСокр='ООО "БПМСОФТ"'),
    )

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.related_companies == [], \
        "организация указана связанной сама с собой"


@respx.mock
async def test_link_labels_are_grammatical():
    """«через руководительа» в отчёте для руководства недопустимо."""
    _mock_cards(_blank(Руковод=[{"ФИО": "Иванов И. И.", "ИНН": "500100732259",
                                 "НаимДолжн": "ДИРЕКТОР"}]))
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    for rc in graph.related_companies:
        assert "ьа" not in rc.link, f"кривой падеж: {rc.link}"


# ─────────────────  баги, найденные разбором кода  ─────────────────

@respx.mock
async def test_deep_summary_declares_unavailable_bailiffs():
    """Отказ приставов при глубокой проверке исчезал бесследно.

    enforcement возвращал SourceResult без данных, и проверка
    «не SourceResult» его не ловила. Организация выглядела так,
    будто долгов у неё нет, — при том что их не искали.
    """
    _mock_cards(
        _blank(СвязУчред=[{"ИНН": "7700000008", "ОГРН": "8",
                           "НаимСокр": 'ООО "Тёмное"'}]),
        default=_blank(ИНН="7700000008", Статус={"Наим": "Ликвидировано"}),
    )
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))
    respx.get(f"{settings.checko_base_url}/inspections").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))
    respx.get(f"{settings.checko_base_url}/enforcements").mock(
        return_value=httpx.Response(503))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    summary = graph.related_companies[0].deep_summary
    assert "НЕ ПРОВЕРЕНО" in summary and "приставы" in summary


@respx.mock
async def test_empty_card_is_not_a_clean_check():
    """Пустая карточка выдавалась за успешно проверенную организацию."""
    respx.get(CARD, params__contains={"inn": BPMSOFT}).mock(
        return_value=httpx.Response(200, json=_wrap(
            _blank(СвязУчред=[{"ИНН": "7700000009", "ОГРН": "9"}]))))
    respx.get(CARD).mock(return_value=httpx.Response(200, json=_wrap({})))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    rc = graph.related_companies[0]
    assert rc.triage_status == "unavailable"
    assert "НЕ ПРОВЕРЕНЫ" in graph.coverage_note


@respx.mock
async def test_controlling_owner_survives_the_people_limit(monkeypatch):
    """При упоре в лимит нельзя выбрасывать владельца ради директоров.

    Порядок лиц в карточке произволен: если контрольный пакет записан
    последним, обрезание по порядку выкинет именно его.
    """
    monkeypatch.setattr(settings, "affiliation_max_people", 1)
    _mock_cards(_blank(
        Руковод=[{"ФИО": "Номинал Н. Н.", "ИНН": "500100732259",
                  "НаимДолжн": "ДИРЕКТОР"}],
        Учред={"ФЛ": [{"ФИО": "Хозяин Х. Х.", "ИНН": "770000000156",
                       "Доля": {"Процент": 90.0}}]},
    ))
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    checked = [p for p in graph.people if p.checked]
    assert len(checked) == 1
    # заглушка /person отвечает одним и тем же профилем, поэтому
    # проверяем по ИНН: важно, кого выбрали, а не что вернул источник
    assert checked[0].inn == "770000000156", "выброшен владелец, оставлен номинал"
    assert checked[0].share_percent == 90.0


@respx.mock
async def test_predecessor_survives_the_related_limit(monkeypatch):
    """Правопреемство важнее рядовых связей и не должно отсекаться."""
    monkeypatch.setattr(settings, "affiliation_max_related", 1)
    _mock_cards(_blank(
        СвязУчред=[{"ИНН": f"770000001{i}", "ОГРН": f"1{i}"} for i in range(4)],
        Правопредш=[{"ИНН": "7700000099", "ОГРН": "99",
                     "НаимСокр": 'ООО "Прошлое"'}],
    ))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    checked = [rc for rc in graph.related_companies
               if rc.triage_status != "not_checked"]
    assert len(checked) == 1
    assert checked[0].link == "правопредшественник"


@respx.mock
async def test_null_share_does_not_crash():
    """Доля, пришедшая пустой, роняла разбор карточки."""
    _mock_cards(_blank(Учред={"РосОрг": [
        {"ИНН": "7700000020", "ОГРН": "20", "НаимСокр": "ООО «Владелец»",
         "Доля": None}]}))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.owner_organizations[0].name == "ООО «Владелец»"
    assert graph.owner_organizations[0].via is None


@respx.mock
async def test_anonymous_person_is_not_duplicated():
    """Директор и учредитель без ИНН — один человек, а не два."""
    _mock_cards(_blank(
        Руковод=[{"ФИО": "Безномеров Б. Б.", "НаимДолжн": "ДИРЕКТОР"}],
        Учред={"ФЛ": [{"ФИО": "Безномеров Б. Б.", "Доля": {"Процент": 50.0}}]},
    ))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert len(graph.people) == 1, "лицо без ИНН задвоилось"
    assert "учредитель" in graph.people[0].role_in_company
    assert graph.people[0].share_percent == 50.0


@respx.mock
async def test_anonymous_person_links_keep_their_kind():
    """Учредительство нельзя подписывать как руководство."""
    _mock_cards(_blank(Учред={"ФЛ": [
        {"ФИО": "Безномеров Б. Б.", "СвязУчред": ["55"]}]}))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.related_companies[0].link == "через учредителя"


@respx.mock
async def test_entrepreneur_graph_is_not_silently_empty():
    """У предпринимателя нет учредителей — но есть он сам.

    Прежде граф выходил пустым и читался как «связей нет».
    """
    ip = "500100732259"
    respx.get(f"{settings.checko_base_url}/entrepreneur").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"ИНН": ip, "ФИО": "Предприниматель П. П."})))
    _mock_person()

    graph, _ = await CheckoSource().check_affiliations(ip, deep=False)

    assert graph.people, "предприниматель не попал в собственный граф"
    assert graph.people[0].role_in_company == "индивидуальный предприниматель"


@respx.mock
async def test_quota_message_reaches_the_user():
    """Сервис объясняет отказ в теле ответа — раньше доходил только код.

    «403» и «превышен суточный лимит для бесплатного тарифа» требуют
    разных действий: во втором случае чинить нечего, надо менять тариф.
    Поймано живым прогоном, когда квота кончилась посреди проверки.
    """
    respx.get(CARD).mock(return_value=httpx.Response(403, json={
        "meta": {"status": "error", "today_request_count": 100,
                 "message": "Превышен суточный лимит запросов для бесплатного тарифа"}}))

    graph, res = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph is None
    assert "суточный лимит" in res.reason


@respx.mock
async def test_quota_message_reaches_triage_too():
    """Та же причина обязана быть видна и на поверхностной проверке."""
    respx.get(CARD, params__contains={"inn": BPMSOFT}).mock(
        return_value=httpx.Response(200, json=_wrap(
            _blank(СвязУчред=[{"ИНН": "7700000030", "ОГРН": "30"}]))))
    respx.get(CARD).mock(return_value=httpx.Response(403, json={
        "meta": {"message": "Превышен суточный лимит запросов"}}))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert graph.related_companies[0].triage_status == "unavailable"
    assert "НЕ ПРОВЕРЕНЫ" in graph.coverage_note


@respx.mock
async def test_foreign_identifier_does_not_reach_the_api():
    """Казахский идентификатор двенадцатизначный, как и российский ИП.

    Без проверки страны он уходил в метод предпринимателей: запрос
    тратился впустую, а отказ выглядел как сбой источника.
    """
    route = respx.get(f"{settings.checko_base_url}/entrepreneur")
    graph, res = await CheckoSource().check_affiliations("990140000385", deep=False)

    assert not route.called, "запрос ушёл в источник, которого по стране нет"
    assert graph is None
    assert "НЕ ПРОВОДИЛАСЬ" in res.reason


# ─────────────────  слой 4б: владельцы без отметок  ─────────────────

def _mock_deep_endpoints(*, cases: dict, enforcements: dict,
                         inspections: dict) -> None:
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap(cases)))
    respx.get(f"{settings.checko_base_url}/enforcements").mock(
        return_value=httpx.Response(200, json=_wrap(enforcements)))
    respx.get(f"{settings.checko_base_url}/inspections").mock(
        return_value=httpx.Response(200, json=_wrap(inspections)))


@respx.mock
async def test_clean_owner_gets_deep_check():
    """Владелец-организация без отметок тоже проверяется глубоко.

    Трудности владельца — это трудности компании: контрольный пакет
    в недоверенных руках, вывод активов через родственное юрлицо.
    Отметки и мёртвый статус этого не ловили — «чистая витрина»
    с тяжёлыми исками проходила как благополучная.
    """
    _mock_cards(
        _blank(Учред={"РосОрг": [{"ИНН": "7700000040", "ОГРН": "40",
                                  "НаимСокр": 'ООО "Владелец"',
                                  "Статус": {"Наим": "Действует"},
                                  "Доля": {"Процент": 100}}]}),
        default=_blank(ИНН="7700000040", Статус={"Наим": "Действует"}),
    )
    _mock_deep_endpoints(
        cases={"Записи": [{"Номер": "А40-9/2024", "Дата": "2024-02-01",
                           "СуммИск": 14_000_000,
                           "Ответ": [{"ИНН": "7700000040"}], "Ист": [],
                           "Суд": "АС Москвы"}],
               "ЗапВсего": 1, "СтрВсего": 1},
        enforcements={"Записи": [], "ОбщКолич": 0},
        inspections={"Записи": [], "ЗапВсего": 0, "СтрВсего": 1},
    )

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    rc = next(r for r in graph.related_companies if r.inn == "7700000040")
    assert rc.deep_summary and "ответчик" in rc.deep_summary
    assert rc.suspicious is True, "иски против владельца не подняли флаг"


@respx.mock
async def test_owner_neutral_activity_is_not_suspicious():
    """Владелец сам взыскивает долги — это работа, а не риск.

    Истец по делам и «судебных дел нет» не должны делать владельца
    подозрительным: иначе почти любой владелец с нормально идущим
    бизнесом краснел бы зря.
    """
    _mock_cards(
        _blank(Учред={"РосОрг": [{"ИНН": "7700000041", "ОГРН": "41",
                                  "НаимСокр": 'ООО "Спокойный"',
                                  "Статус": {"Наим": "Действует"}}]}),
        default=_blank(ИНН="7700000041", Статус={"Наим": "Действует"}),
    )
    _mock_deep_endpoints(
        cases={"Записи": [{"Номер": "А40-2/2024", "Дата": "2024-01-01",
                           "СуммИск": 900_000,
                           "Ответ": [], "Ист": [{"ИНН": "7700000041"}],
                           "Суд": "АС Москвы"}],
               "ЗапВсего": 1, "СтрВсего": 1},
        enforcements={"Записи": [], "ОбщКолич": 0},
        inspections={"Записи": [], "ЗапВсего": 0, "СтрВсего": 1},
    )

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    rc = next(r for r in graph.related_companies if r.inn == "7700000041")
    assert rc.suspicious is False
    assert rc.deep_summary and "истец" in rc.deep_summary


@respx.mock
async def test_owner_unchecked_direction_is_declared():
    """Отказ приставов по владельцу не должен читаться как «долгов нет»."""
    _mock_cards(
        _blank(Учред={"РосОрг": [{"ИНН": "7700000042", "ОГРН": "42",
                                  "НаимСокр": 'ООО "Тихий"',
                                  "Статус": {"Наим": "Действует"}}]}),
        default=_blank(ИНН="7700000042", Статус={"Наим": "Действует"}),
    )
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))
    respx.get(f"{settings.checko_base_url}/enforcements").mock(
        return_value=httpx.Response(503))
    respx.get(f"{settings.checko_base_url}/inspections").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))

    graph, _ = await CheckoSource().check_affiliations(BPMSOFT, deep=True)

    rc = next(r for r in graph.related_companies if r.inn == "7700000042")
    assert rc.deep_summary and "НЕ ПРОВЕРЕНО" in rc.deep_summary
    assert "приставы" in rc.deep_summary
    assert rc.suspicious is False, "отказ источника — не признак"


@respx.mock
async def test_owner_deep_skipped_when_fast():
    """deep=False — дешёвый режим, владельцев глубоко не проверяем."""
    _mock_cards(
        _blank(Учред={"РосОрг": [{"ИНН": "7700000043", "ОГРН": "43",
                                  "НаимСокр": 'ООО "Быстрый"',
                                  "Статус": {"Наим": "Действует"}}]}),
        default=_blank(ИНН="7700000043", Статус={"Наим": "Действует"}),
    )
    route = respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_wrap(
            {"Записи": [], "ЗапВсего": 0, "СтрВсего": 1})))

    await CheckoSource().check_affiliations(BPMSOFT, deep=False)

    assert not route.called, "глубокая проверка ушла в быстром режиме"
