"""Подтверждение принадлежности сайта организации.

Наивный подход — требовать ИНН в подвале сайта — неверен: у множества
настоящих сайтов реквизитов нет вовсе (продуктовые лендинги, англоязычные
версии, промо-страницы). Отбраковав такой сайт, мы не установим рыночное
наименование, будем искать по юридическому, ничего не найдём и сообщим
«негатива нет» — то есть придём ровно к той ошибке, от которой защищаемся.

Поэтому здесь не пропускной пункт, а НАКОПЛЕНИЕ независимых признаков.
Сработавшие признаки сохраняются: решение должно быть объяснимым.
"""

import re
import unicodedata

from pydantic import BaseModel, Field

from osint_mcp.models import CompanyContext, Confidence

# Вес признака отражает, насколько трудно ему совпасть случайно
WEIGHTS = {
    "inn": 3,
    "ogrn": 3,
    "legal_name": 2,
    "short_name": 2,
    "email_domain": 2,
    "phone": 2,
    "brand": 1,
    "city": 1,
}

THRESHOLD_HIGH = 3
THRESHOLD_MEDIUM = 2


class DomainMatch(BaseModel):
    """Насколько уверенно сайт принадлежит организации."""

    domain: str = Field(description="Проверявшийся домен")
    confidence: Confidence = Field(
        description=(
            "high — принадлежность подтверждена; medium — вероятна, годится "
            "для поиска, но не для утверждений; low — не подтверждена"
        )
    )
    score: int = Field(description="Сумма весов сработавших признаков")
    signals: list[str] = Field(
        default_factory=list, description="Какие именно признаки совпали"
    )
    note: str | None = Field(default=None, description="Пояснение для агента")


def _normalize(text: str) -> str:
    """Убрать регистр, кавычки и лишние пробелы — сравнение должно быть терпимым."""
    text = unicodedata.normalize("NFKC", text).lower()
    text = re.sub(r"[«»\"'`„“”]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


# Русские слова в тексте склоняются: в реестре «Москва», на странице
# «в Москве». Точное вхождение подстроки на этом ломается, поэтому для
# слов, которые могут стоять в косвенном падеже, сравниваем по основе.
_MAX_ENDING = 2
_MIN_STEM = 4


def _stem(word: str) -> str:
    """Отбросить окончание. Грубо, но для сопоставления названий достаточно."""
    word = _normalize(word)
    if len(word) <= _MIN_STEM:
        return word
    return word[: max(_MIN_STEM, len(word) - _MAX_ENDING)]


def _contains_declined(haystack: str, word: str) -> bool:
    """Встречается ли слово в тексте в любом падеже."""
    if not word:
        return False
    if _normalize(word) in haystack:
        return True
    return _stem(word) in haystack


def verify_domain(
    domain: str,
    page_text: str,
    ctx: CompanyContext,
    page_title: str = "",
    registry_emails: list[str] | None = None,
    registry_phones: list[str] | None = None,
) -> DomainMatch:
    """Подтвердить, что сайт принадлежит организации.

    Не требует какого-то одного признака: достаточно нескольких слабых.
    """
    haystack = _normalize(page_text)
    haystack_digits = _digits(page_text)
    title = _normalize(page_title)
    signals: list[str] = []

    if ctx.inn and ctx.inn in haystack_digits:
        signals.append("inn")
    if ctx.ogrn and ctx.ogrn in haystack_digits:
        signals.append("ogrn")

    if ctx.name_legal and _normalize(ctx.name_legal) in haystack:
        signals.append("legal_name")
    if ctx.name_short and _normalize(ctx.name_short) in haystack:
        signals.append("short_name")

    # Домен почты из реестра, совпадающий с сайтом, — сильный признак
    root = domain.lower().removeprefix("www.")
    for email in (registry_emails or []):
        if "@" in email and email.split("@")[-1].lower().removeprefix("www.") == root:
            signals.append("email_domain")
            break

    for phone in (registry_phones or []):
        tail = _digits(phone)[-10:]
        if len(tail) == 10 and tail in haystack_digits:
            signals.append("phone")
            break

    if ctx.brand:
        brand = _normalize(ctx.brand)
        if (brand and (brand.replace(" ", "") in root
                       or _contains_declined(title, ctx.brand)
                       or _contains_declined(haystack, ctx.brand))):
            signals.append("brand")

    # Город почти всегда стоит в косвенном падеже: «офис в Москве»
    if ctx.city and _contains_declined(haystack, ctx.city):
        signals.append("city")

    score = sum(WEIGHTS[s] for s in signals)
    if score >= THRESHOLD_HIGH:
        confidence: Confidence = "high"
        note = None
    elif score >= THRESHOLD_MEDIUM:
        confidence = "medium"
        note = ("Принадлежность сайта вероятна, но не доказана. Использовать "
                "для поиска можно, утверждать в отчёте — нельзя.")
    else:
        confidence = "low"
        note = ("Принадлежность сайта не подтверждена. Не выдавай сведения "
                "с него за сведения об этой организации.")

    return DomainMatch(domain=domain, confidence=confidence,
                       score=score, signals=signals, note=note)
