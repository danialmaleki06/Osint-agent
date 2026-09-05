"""Тесты подтверждения принадлежности сайта.

Ключевое требование: отсутствие ИНН на странице НЕ является основанием
отбраковать сайт. Настоящих сайтов без реквизитов много, а ошибочная
отбраковка приводит к ложному выводу «негативных упоминаний нет».
"""

from osint_mcp.models import CompanyContext
from osint_mcp.tools.domain_match import WEIGHTS, verify_domain

CTX = CompanyContext(
    inn="7724744134",
    ogrn="1107746293049",
    name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"',
    name_short='ООО "БПМСОФТ"',
    city="Москва",
    brand="BPMSoft",
)


def test_inn_alone_is_enough():
    """Реквизиты в подвале — самое надёжное подтверждение."""
    page = "Реквизиты: ИНН 7724744134, КПП 771501001"
    r = verify_domain("bpmsoft.ru", page, CTX)

    assert r.confidence == "high"
    assert "inn" in r.signals


def test_site_without_requisites_still_passes():
    """ГЛАВНОЕ: сайт без ИНН не должен отбраковываться.

    Продуктовый лендинг может не содержать реквизитов вовсе. Бренда в
    заголовке, названия и города достаточно, чтобы признать сайт своим.
    """
    page = ("BPMSoft — low-code платформа для автоматизации. "
            "Офис в Москве. ООО \"БПМСОФТ\"")
    r = verify_domain("bpmsoft.ru", page, CTX, page_title="BPMSoft — CRM и BPM")

    assert "inn" not in r.signals          # реквизитов нет
    assert r.confidence == "high"          # и всё равно подтверждено
    assert {"brand", "short_name", "city"} & set(r.signals)


def test_weak_single_signal_is_not_enough():
    """Одного слабого совпадения мало: «Москва» есть на миллионе сайтов."""
    r = verify_domain("random.ru", "Компания из города Москва", CTX)

    assert r.confidence == "low"
    assert r.signals == ["city"]
    assert "не подтверждена" in r.note


def test_two_weak_signals_give_medium():
    """Слабых признаков вместе хватает на «вероятно», но не на «точно»."""
    r = verify_domain("x.ru", "Москва", CTX, page_title="BPMSoft")

    assert r.confidence == "medium"
    assert "утверждать в отчёте — нельзя" in r.note


def test_foreign_company_site_is_rejected():
    """Чужой сайт не должен пройти. Проверка на подставленном домене."""
    page = "Cardsmile — сервис подарочных карт. ИНН 9999999999"
    r = verify_domain("cardsmile.ru", page, CTX)

    assert r.confidence == "low"
    assert "inn" not in r.signals


def test_email_domain_from_registry_counts():
    r = verify_domain("bpmsoft.ru", "Свяжитесь с нами", CTX,
                      registry_emails=["info@bpmsoft.ru"])
    assert "email_domain" in r.signals


def test_phone_from_registry_counts():
    r = verify_domain("bpmsoft.ru", "Телефон: +7 (495) 287-32-57", CTX,
                      registry_phones=["+74952873257"])
    assert "phone" in r.signals


def test_signals_are_recorded_for_audit():
    """Решение должно быть объяснимым: видно, на чём оно основано."""
    page = 'ИНН 7724744134. ООО "БПМСОФТ", Москва'
    r = verify_domain("bpmsoft.ru", page, CTX)

    assert {"inn", "short_name", "city"} <= set(r.signals)
    assert r.score == sum(WEIGHTS[s] for s in r.signals)   # балл сходится с признаками
    assert len(set(r.signals)) == len(r.signals)           # без повторов


def test_quotes_and_case_do_not_break_matching():
    """Сравнение терпимо к регистру и кавычкам разных видов."""
    page = 'общество с ограниченной ответственностью «бпмсофт»'
    r = verify_domain("bpmsoft.ru", page, CTX)

    assert "legal_name" in r.signals


def test_declension_does_not_break_city_match():
    """Русские слова склоняются: в реестре «Москва», на странице «в Москве».

    Точное вхождение подстроки на этом ломается, поэтому сравнение идёт
    по основе слова.
    """
    for text in ("Офис в Москве", "Компания из Москвы", "г. Москва", "по Москве"):
        r = verify_domain("x.ru", text, CTX)
        assert "city" in r.signals, text


def test_other_city_still_does_not_match():
    """Сравнение по основе не должно склеивать разные города."""
    r = verify_domain("x.ru", "Офис в Казани", CTX)
    assert "city" not in r.signals
