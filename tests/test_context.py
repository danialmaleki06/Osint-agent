"""Тесты источника контекста.

respx подменяет транспорт httpx: реальных запросов нет, ключи не нужны,
результат детерминированный. Когда появится рабочий ключ, эти образцы
ответов заменим на записанные с живого API.
"""

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.tools.context_builder import build_company_context

pytestmark = pytest.mark.anyio

SUGGEST_URL = f"{settings.dadata_base_url}/suggest/party"
FIND_URL = f"{settings.dadata_base_url}/findById/party"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    """Подставляем ключ, чтобы require() не падал. Наружу запросов всё равно нет."""
    monkeypatch.setattr(settings, "dadata_api_key", "test-key")


def _party(inn="7707083893", name='ПАО "СБЕРБАНК"', status="ACTIVE",
           city="Москва", okved="64.19", reg_ms=741398400000):
    return {
        "value": name,
        "data": {
            "inn": inn,
            "ogrn": "1027700132195",
            "name": {"full_with_opf": name, "short_with_opf": name.split()[-1]},
            "address": {"value": f"{city}, ул. Вавилова, 19",
                        "data": {"city": city, "region_with_type": "г Москва"}},
            "state": {"status": status, "registration_date": reg_ms},
            "management": {"name": "Греф Герман Оскарович", "post": "Президент"},
            "okved": okved,
            "okved_type": "Денежное посредничество прочее",
            "capital": {"value": 67760844000.0},
            "founders": [],
        },
    }


# ───────────────────────────  get_context  ───────────────────────────

@respx.mock
async def test_context_is_assembled():
    respx.post(FIND_URL).mock(
        return_value=httpx.Response(200, json={"suggestions": [_party()]})
    )
    res = await DaDataSource().get_context("7707083893")

    assert res.status == "ok"
    ctx = res.context
    assert ctx.inn == "7707083893"
    assert ctx.city == "Москва"
    assert ctx.director_fio == "Греф Герман Оскарович"
    assert ctx.registered_at is not None


@respx.mock
async def test_context_derives_variants_and_terms():
    """Производные поля должны выводиться, а не приходить из источника."""
    respx.post(FIND_URL).mock(
        return_value=httpx.Response(
            200, json={"suggestions": [_party(name='ООО "ТД Вектор-2011"',
                                              okved="41.20")]}
        )
    )
    ctx = (await DaDataSource().get_context("7707083893")).context

    assert "Вектор-2011" in ctx.name_variants      # снята форма и приставка
    assert "застройщик" in ctx.industry_terms      # выведено из ОКВЭД 41
    assert ctx.brand_resolved is False             # рыночное имя ещё не искали


async def test_bad_inn_never_reaches_api():
    """Опечатка отсекается локально — ни одного обращения наружу."""
    with respx.mock:
        route = respx.post(FIND_URL)
        res = await DaDataSource().get_context("7707083899")
        assert res.status == "skipped"
        assert not route.called


@respx.mock
async def test_source_failure_is_not_empty_result():
    """Недоступность источника обязана отличаться от «данных нет»."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(500))
    res = await DaDataSource().get_context("7707083893")

    assert res.status == "unavailable"
    assert res.context is None
    assert "500" in res.reason


# ───────────────────────────  resolve  ───────────────────────────

@respx.mock
async def test_resolve_by_inn_is_confident():
    respx.post(FIND_URL).mock(
        return_value=httpx.Response(200, json={"suggestions": [_party()]})
    )
    res = await DaDataSource().resolve("7707083893")
    assert res.confidence == "high"
    assert res.total_found == 1


@respx.mock
async def test_ambiguous_name_refuses_to_choose():
    """Ключевая проверка этапа: при неоднозначности выбор остаётся за человеком."""
    many = [_party(inn=f"770708389{i}", city=c)
            for i, c in enumerate(["Москва", "Казань", "Пермь"])]
    respx.post(SUGGEST_URL).mock(
        return_value=httpx.Response(200, json={"suggestions": many})
    )
    res = await DaDataSource().resolve("Ромашка")

    assert res.confidence == "low"
    assert res.total_found == 3
    assert "НЕ выбирай сам" in res.hint
    # города различают кандидатов
    assert {c.city for c in res.candidates} == {"Москва", "Казань", "Пермь"}


@respx.mock
async def test_single_active_among_liquidated_is_medium():
    items = [_party(inn="7707083893", status="ACTIVE"),
             _party(inn="5024112233", status="LIQUIDATED")]
    respx.post(SUGGEST_URL).mock(
        return_value=httpx.Response(200, json={"suggestions": items})
    )
    res = await DaDataSource().resolve("Ромашка")

    assert res.confidence == "medium"
    assert any(c.status == "ликвидирована" for c in res.candidates)


@respx.mock
async def test_nothing_found_is_not_ambiguity():
    """«Не найдено» и «выберите из нескольких» — разные состояния.

    Прежде оба отдавались как confidence="low". По описанию инструмента
    агент при "low" обязан показать пользователю перечень кандидатов —
    а перечень пуст, и показывать нечего. Поймано живым прогоном.
    """
    respx.post(SUGGEST_URL).mock(
        return_value=httpx.Response(200, json={"suggestions": []})
    )
    res = await DaDataSource().resolve("Такогонетнасвете")

    assert res.confidence == "none"
    assert res.total_found == 0
    assert res.candidates == []
    assert res.hint and "не найдена" in res.hint
    # и агенту прямо запрещено объявлять о несуществовании компании
    assert "не существует" in res.hint


@respx.mock
async def test_hint_is_never_empty_on_success():
    """В описании инструмента агенту велено прочесть hint.

    На самом частом, успешном пути поле было пустым, и агент
    оставался без указаний. Поймано живым прогоном.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))

    res = await DaDataSource().resolve("7707083893")

    assert res.confidence == "high"
    assert res.hint, "подсказка пуста при однозначном определении"
    assert res.candidates[0].inn in res.hint, "в подсказке нет ИНН выбранной организации"


# ───────────────────────────  филиалы  ───────────────────────────

def _branch(inn="7707083893", name="БАЙКАЛЬСКИЙ БАНК ПАО СБЕРБАНК", city="Иркутск"):
    item = _party(inn=inn, name=name, city=city)
    item["data"]["branch_type"] = "BRANCH"
    return item


def _head(**kw):
    item = _party(**kw)
    item["data"]["branch_type"] = "MAIN"
    return item


@respx.mock
async def test_branches_are_collapsed_on_inn_search():
    """Поиск по ИНН возвращает головную организацию и филиалы с тем же ИНН."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_head(), _branch(), _branch(city="Хабаровск")]}))

    res = await DaDataSource().resolve("7707083893")
    assert res.confidence == "high"
    assert res.total_found == 1                 # филиалы схлопнуты
    assert "Филиалов" in res.hint


@respx.mock
async def test_context_takes_head_office_not_branch():
    """Даже если филиал пришёл первым, карточка собирается на головную."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_branch(), _head(name='ПАО "СБЕРБАНК РОССИИ"')]}))

    ctx = (await DaDataSource().get_context("7707083893")).context
    assert "БАЙКАЛЬСКИЙ" not in ctx.name_legal


# ─────────────────  молчаливые пробелы в карточке  ─────────────────

@respx.mock
async def test_dead_checko_leaves_a_trace():
    """Отказ обогащающего источника обязан быть виден в ответе.

    Карточка собирается из двух служб. Если вторая молчит, поля
    size_category, employees, capital и former_names остаются пустыми —
    и это неотличимо от «таких сведений не существует». Поймано при
    разборе, почему после смены ключа агенты получали пустую карточку.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))
    respx.post(settings.dadata_brand_url).mock(return_value=httpx.Response(
        200, json={"suggestions": [{"data": {"brand": "Тест"}}]}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    # весь второй источник лежит
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(403, json={
            "meta": {"message": "Превышен суточный лимит запросов"}}))
    # бесплатный эшелон тоже должен быть замокан: фолбэк финансов на ГИР БО
    # вызывается при отказе платного, и без моков тест упадёт на внешнем вызове
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(503))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(503))
    # найм по hh: без мока тест уходит во внешний вызов
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    assert res.status == "ok"
    assert res.reason, "источник молчал, а в ответе об этом ни слова"
    assert "НЕ УСТАНОВЛЕН" in res.reason
    assert "НЕ ПРОВЕРЕНЫ" in res.reason
    # и прямой запрет на неверное прочтение пустоты
    assert "не потому что сведений нет" in res.reason
    assert "НЕ означает" in res.reason
    assert res.context.size_category == "unknown"
    assert res.context.former_names == []


@respx.mock
async def test_branch_count_comes_from_the_complete_source():
    """Число филиалов берётся из карточки, а не из поисковой выдачи.

    Справочник по ИНН отдаёт не больше десяти записей: у Сбербанка
    вместо 87 филиалов вышло бы 9. Проверено на живых данных.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(f"{settings.checko_base_url}/finances").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {}}))
    respx.get(f"{settings.checko_base_url}/timeline").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": []}))
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {
            "СЧР": 100,
            "Подразд": {"Филиал": [{"КПП": str(i)} for i in range(87)],
                        "Представ": [{"КПП": "1"}]},
        }}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    assert res.context.branches == 87
    assert res.context.representative_offices == 1


@respx.mock
async def test_branch_count_unknown_is_not_zero():
    """Если карточка не пришла, число филиалов НЕ УСТАНОВЛЕНО, а не ноль."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(503))
    # бесплатный эшелон замокан: ГИР БО отвечает, но компания в ресурсе
    # не значится — фолбэк отрабатывает и не влияет наbranches=None
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": []}))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    assert res.context.branches is None, "отказ источника выдан за отсутствие филиалов"
    assert "НЕ УСТАНОВЛЕН" in res.reason


# ─────────────────  ссылки на первоисточники  ─────────────────

@respx.mock
async def test_source_links_collected_even_when_sources_fail():
    """Карточка есть — карточка ЕГРЮЛ в ссылках есть, от чего бы то ни было.

    Ссылки собираются всегда при сборе контекста, но в отчёты не идут:
    их отдаёт дозапрос get_company_links.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(503))
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": []}))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    links = res.context.source_links
    assert links, "ссылка на карточку реестра пропала при отказе обогащений"
    card = next(l for l in links if "ЕГРЮЛ" in l.what)
    # Контур по ОГРН: ИНН-формат карточек Checko отдаёт 404 (живая проверка)
    assert card.url == "https://focus.kontur.ru/entity?query=1027700132195"
    # Обогащения пали — финансовых ссылок нет, и это честно
    assert all(l.source != "bo_nalog" for l in links)


@respx.mock
async def test_profile_heuristics_product_vs_outsourced():
    """Товарный знак у ИТ-компании — продуктовая; без знака по 62.02 — подряд."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party(okved="62.01")]}))
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(f"{settings.checko_base_url}/finances").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {}}))
    respx.get(f"{settings.checko_base_url}/timeline").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": []}))
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {
            # Товарный знак при основном 62.01 — признак продукта
            "ТоварЗнак": [{"Наим": "БПМСОФТ"}],
        }}))
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": []}))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    assert res.context.business_model == "product"


@respx.mock
async def test_it_okved_gets_registry_link():
    """ОКВЭД 62/63 — эвристика ИТ-компании: ссылка на официальный реестр
    Минцифры для точной проверки (бесплатного API реестра нет)."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party(okved="62.01")]}))
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(503))
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": []}))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))

    res = await build_company_context("7707083893")

    links = res.context.source_links
    it_link = next((l for l in links if l.source == "mincifry_registry"), None)
    assert it_link is not None, "для ОКВЭД 62.xx нет ссылки на реестр ИТ"
    assert "gosuslugi.ru/itorgs" in it_link.url
    assert "62.01" in it_link.what


DDG_URL = "https://lite.duckduckgo.com/lite/"


def _mock_free_tier_base():
    """Общие моки бесплатного эшелона для тестов сборки контекста."""
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.post(f"{settings.dadata_base_url}/suggest/okved2").mock(
        return_value=httpx.Response(200, json={"suggestions": []}))
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": []}))
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__regex=rf"{settings.hh_base_url}/.*").mock(
        return_value=httpx.Response(403))


@respx.mock
async def test_fssp_manual_link_always_present():
    """Ссылка на банк данных ФССП собирается всегда: точная проверка долгов
    по ИНН возможна только вручную (автопоиск приблизителен, API — по ключу)."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))
    _mock_free_tier_base()
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(503))
    respx.post(DDG_URL).mock(return_value=httpx.Response(200, text="none"))

    res = await build_company_context("7707083893")

    fssp = next((l for l in res.context.source_links if l.source == "fssp_manual"), None)
    assert fssp is not None, "ссылка на ФССП пропала"
    assert "fssp.gov.ru/iss/ip" in fssp.url and "7707083893" in fssp.url


@respx.mock
async def test_brand_falls_back_to_trademark():
    """Платный метод бренда недоступен → товарный знак из карточки.

    Пробел «рыночное наименование не установлено» ломал репутационный
    поиск: знак — бесплатный намёк на бренд из уже полученной карточки.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party(okved="62.01")]}))
    _mock_free_tier_base()
    respx.get(f"{settings.checko_base_url}/finances").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {}}))
    respx.get(f"{settings.checko_base_url}/timeline").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": []}))
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {
            "ТоварЗнак": [{"Наим": "ВЕКТОР"}],
        }}))

    res = await build_company_context("7707083893")

    ctx = res.context
    assert ctx.brand_resolved is True
    assert ctx.brand == "ВЕКТОР"
    assert "ВЕКТОР" in ctx.name_variants
    assert "товарного знака" in (res.reason or "")


@respx.mock
async def test_brand_falls_back_to_web_search(monkeypatch):
    monkeypatch.setattr("osint_mcp.context.site._query_whois", lambda d, s: "")
    monkeypatch.setattr("osint_mcp.context.site._check_ssl_sync", lambda h: None)
    """Без знаков и с мёртвым реестровым сайтом бренд ищется веб-поиском.

    Сайт из реестра не отвечает → DDG находит официальный сайт по имени →
    сайт открывается и отвечает своим именем → домен становится брендом.
    """
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party(name='ООО "РОМАШКА"', okved="62.01")]}))
    _mock_free_tier_base()
    respx.get(f"{settings.checko_base_url}/finances").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {}}))
    respx.get(f"{settings.checko_base_url}/timeline").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": []}))
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {
            # Сайт из реестра мёртв (как cardsmile.ru у БПМСОФТ)
            "Контакты": {"ВебСайт": "http://dead-registry-site.ru"},
        }}))
    respx.get("http://dead-registry-site.ru").mock(
        return_value=httpx.Response(200, text="<html><body>заглушка без h1</body></html>"))
    # DDG находит официальный сайт
    respx.post(DDG_URL).mock(return_value=httpx.Response(200, text=(
        "<td class='result-link'><a class='result-link' "
        "href='https://romashka.ru/about'>РОМАШКА — официальный сайт</a></td>")))
    respx.get("https://romashka.ru/about").mock(
        return_value=httpx.Response(200, text="<html><h1>Ромашка — софт для бизнеса</h1></html>"))
    # После выбора бренда обогащение снимает самоназвание с корня домена
    respx.get("https://romashka.ru").mock(
        return_value=httpx.Response(200, text="<html><h1>Ромашка — софт для бизнеса</h1></html>"))

    res = await build_company_context("7707083893")

    ctx = res.context
    assert ctx.brand_resolved is True
    assert ctx.brand == "ROMASHKA"
    assert ctx.brand_domain == "https://romashka.ru", "хранится корень, не глубинная страница"
    assert "официальному сайту" in (res.reason or "")


@respx.mock
async def test_brand_gap_honest_when_all_fallbacks_fail():
    """Ни знака, ни сайта, поисковик молчит — пробел остаётся честным."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party(name='ООО "РОМАШКА"', okved="62.01")]}))
    _mock_free_tier_base()
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(503))
    respx.post(DDG_URL).mock(return_value=httpx.Response(200, text="no results here"))

    res = await build_company_context("7707083893")

    assert res.context.brand_resolved is False
    assert "Рыночное наименование не установлено" in (res.reason or "")


# ─────────────────  иностранные идентификаторы на входе  ─────────────────

BY_URL = f"{settings.dadata_base_url}/findById/party_by"
KZ_URL = f"{settings.dadata_base_url}/findById/party_kz"


@respx.mock
async def test_kazakh_identifier_is_not_called_a_typo():
    """БИН Казахстана двенадцатизначный, как и ИНН физлица России.

    Точка входа не определяла страну и гнала номер через российскую
    контрольную сумму. Пользователю сообщалось «ИНН некорректен,
    вероятна опечатка» про совершенно правильный номер. Поймано
    живым прогоном.
    """
    route = respx.post(KZ_URL).mock(return_value=httpx.Response(200, json={
        "suggestions": [{"value": "АССОЦИАЦИЯ БАНКОВ", "data": {
            "bin": "931040001411", "name_ru": "АССОЦИАЦИЯ БАНКОВ",
            "status": "ACTIVE", "address_settlement_ru": "Алматы"}}]}))

    res = await DaDataSource().resolve("931040001411")

    assert route.called, "запрос ушёл не в казахский справочник"
    assert res.confidence == "high"
    assert res.candidates[0].inn == "931040001411"
    assert "некорректен" not in (res.hint or ""), "правильный номер назван ошибочным"
    assert "Казахстан" in (res.hint or ""), "в подсказке нет оговорки о стране"


@respx.mock
async def test_belarusian_identifier_reaches_its_registry():
    """УНП Беларуси искался в российском реестре и объявлялся ненайденным."""
    route = respx.post(BY_URL).mock(return_value=httpx.Response(200, json={
        "suggestions": [{"value": 'ОДО "БАНКАР"', "data": {
            "unp": "191309167", "full_name_ru": 'ОДО "БАНКАР"',
            "status": "ACTIVE"}}]}))

    res = await DaDataSource().resolve("191309167")

    assert route.called
    assert res.confidence == "high"
    assert res.candidates[0].inn == "191309167"
    assert "Беларус" in (res.hint or "")


@respx.mock
async def test_foreign_not_found_is_still_not_nonexistent():
    """Ненайденная иностранная организация — не доказательство её отсутствия."""
    respx.post(KZ_URL).mock(return_value=httpx.Response(200, json={"suggestions": []}))

    res = await DaDataSource().resolve("931040001411")

    assert res.confidence == "none"
    assert res.candidates == []
    assert "не существует" in (res.hint or "")


@respx.mock
async def test_russian_path_is_untouched_by_country_check():
    """Проверка страны не должна ломать обычный российский запрос."""
    respx.post(FIND_URL).mock(return_value=httpx.Response(
        200, json={"suggestions": [_party()]}))

    res = await DaDataSource().resolve("7707083893")

    assert res.confidence == "high"
    assert res.candidates[0].inn == "7707083893"
