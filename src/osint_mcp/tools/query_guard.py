"""Детектор расхождения между запрошенным именем компании и данными по ИНН.

Защищает от ситуаций, когда пользователь или агент запрашивают досье
на одну организацию (например, ООО «ПСО «Казань»), но передают ИНН
совершенно другого юридического лица (например, Управления Роспотребнадзора).
"""

import re
from datetime import datetime, timezone
from typing import Any
from osint_mcp.models import CompanyContext, Fact

# Стоп-слова: правовые формы и общие организационные токены
_STOP_WORDS = {
    "ооо", "пао", "зао", "ао", "нко", "ано", "ип", "муп", "гуп", "фгуп",
    "общество", "ограниченной", "ответственностью", "акционерное", "публичное",
    "компания", "группа", "холдинг", "предприятие", "организация", "центр",
    "инн", "огрн", "кпп", "бик", "гбу", "гку", "мку", "казенное", "бюджетное",
}


def _tokenize(text: str) -> set[str]:
    """Разбивает текст на значимые поисковые токены (длиной >= 3 символов)."""
    if not text:
        return set()
    cleaned = re.sub(r"[^\w\s-]", " ", text.lower(), flags=re.UNICODE)
    tokens = set()
    for raw in cleaned.split():
        tok = raw.strip("-")
        if len(tok) >= 3 and tok not in _STOP_WORDS and not tok.isdigit():
            tokens.add(tok)
    return tokens


def extract_inn_and_name(query: str) -> tuple[str | None, str | None]:
    """Извлекает из сырой строки запроса ИНН и текстовое название.
    
    Пример:
        'ООО «ПСО «Казань» (ИНН 1655065057)' -> ('1655065057', 'ООО «ПСО «Казань»')
        '7724744134' -> ('7724744134', None)
    """
    if not query:
        return None, None
    q = query.strip()
    m_inn = re.search(r"\b(\d{10}|\d{12})\b", q)
    if not m_inn:
        return None, q if len(q) >= 2 else None
    
    inn = m_inn.group(1)
    # Удаляем найденный ИНН и маркеры вроде "ИНН", скобки
    name_part = q[:m_inn.start()] + " " + q[m_inn.end():]
    name_clean = re.sub(r"\bинн\b", " ", name_part, flags=re.IGNORECASE)
    name_clean = re.sub(r"[\(\)\[\]:,]", " ", name_clean).strip()
    name_clean = re.sub(r"\s+", " ", name_clean)
    
    return inn, name_clean if len(name_clean) >= 2 else None


def calculate_name_similarity(expected_name: str, ctx: CompanyContext) -> tuple[float, set[str], set[str]]:
    """Вычисляет коэффициент сходства между ожидаемым именем и зарегистрированными именами в ЕГРЮЛ."""
    if not expected_name or not ctx:
        return 1.0, set(), set()
    
    expected_tokens = _tokenize(expected_name)
    if not expected_tokens:
        return 1.0, set(), set()
    
    # Собираем все официальные наименования и бренд
    resolved_texts = [
        ctx.name_legal or "",
        ctx.name_short or "",
        ctx.brand or "",
        *(ctx.name_variants or ()),
        *(ctx.former_names or ()),
    ]
    resolved_tokens = set()
    for t in resolved_texts:
        resolved_tokens.update(_tokenize(t))
    
    if not resolved_tokens:
        return 1.0, expected_tokens, set()
    
    # 1. Точное пересечение токенов
    direct_overlap = expected_tokens.intersection(resolved_tokens)
    
    # 2. Нечеткое вхождение (один токен является подстрокой другого, например 'псо' в 'псинтез' или 'bpmsoft' в 'bpm')
    fuzzy_matches = set()
    for et in expected_tokens:
        if et in direct_overlap:
            continue
        for rt in resolved_tokens:
            if len(et) >= 3 and len(rt) >= 3:
                if et in rt or rt in et:
                    fuzzy_matches.add(et)
                    break
    
    matched_tokens = direct_overlap.union(fuzzy_matches)
    similarity = len(matched_tokens) / len(expected_tokens)
    return round(similarity, 3), expected_tokens, resolved_tokens


def check_query_inn_consistency(
    query_or_expected: str | None,
    ctx: CompanyContext | None,
) -> dict[str, Any] | None:
    """Проверяет соответствие между запрошенным именем компании и данными по ИНН.
    
    Возвращает dict с деталями расхождения, если обнаружено несоответствие (сходство < 0.35).
    """
    if not query_or_expected or not ctx:
        return None
    
    _, expected_name = extract_inn_and_name(query_or_expected)
    if not expected_name:
        expected_name = query_or_expected.strip()
    
    similarity, expected_toks, resolved_toks = calculate_name_similarity(expected_name, ctx)
    
    # Если сходство < 0.35 и было указано хотя бы одно значимое слово
    if similarity < 0.35 and expected_toks:
        actual_name = ctx.name_short or ctx.name_legal or "Не установлено"
        return {
            "запрошено_наименование": expected_name,
            "фактическое_в_реестре": actual_name,
            "инн": ctx.inn,
            "коэффициент_сходства": similarity,
            "критичность": "high",
            "предупреждение": (
                f"КРИТИЧЕСКОЕ РАСХОЖДЕНИЕ РЕКВИЗИТОВ: Запрошена компания «{expected_name}», "
                f"однако по ИНН {ctx.inn} в ЕГРЮЛ зарегистрирована организация «{actual_name}». "
                f"Коэффициент сходства наименований {int(similarity * 100)}%. "
                f"Вероятно, передан ошибочный ИНН чужой организации."
            ),
        }
    
    return None


def build_discrepancy_fact(discrepancy: dict[str, Any]) -> Fact:
    """Создает нормализованный Fact для риск-скоринга и отчета."""
    return Fact(
        fact_id="RISK-QUERY-NAME-MISMATCH",
        kind="registry",
        statement=discrepancy["предупреждение"],
        source_url="https://egrul.nalog.ru/",
        source_type="egrul",
        retrieved_at=datetime.now(timezone.utc),
        payload=discrepancy,
    )
