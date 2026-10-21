"""Отчёт о полноте проверки организации.

Собирается из журнала обращений, а не из памяти модели: сложить статусы
за четыре вызова и ничего не потерять — работа, которую модель выполняет
ненадёжно. Ровно поэтому мы не поручаем ей и подсчёт процессуальных ролей.

Отчёт отвечает на три вопроса: куда ходили, что получили, чего не
получили и почему. Третий важнее первых двух: «источник молчал»
и «сведений действительно нет» ведут к противоположным выводам.
"""

import structlog

from osint_mcp import ledger
from osint_mcp.models import CoverageReport, DataGap, ServiceUsage

log = structlog.get_logger()

# Что даёт каждое направление. Ключ — служба и метод, как они пишутся
# в журнале; значение — человеческое название сведений.
MEANING: dict[tuple[str, str], str] = {
    ("dadata", "findById/party"): "реквизиты из государственного реестра",
    ("dadata", "suggest/party"): "поиск организации по названию",
    ("dadata", "findById/brand"): "рыночное наименование и сайт",
    ("dadata", "suggest/okved2"): "расшифровка вида деятельности",
    ("dadata", "findById/party_by"): "реквизиты организации Беларуси",
    ("dadata", "findById/party_kz"): "реквизиты организации Казахстана",
    ("checko", "company"): "карточка организации: отметки, учредители, филиалы",
    ("checko", "entrepreneur"): "карточка индивидуального предпринимателя",
    ("checko", "finances"): "финансовые показатели и численность",
    ("checko", "timeline"): "прежние наименования и смены руководителя",
    ("checko", "legal-cases"): "арбитражные дела",
    ("checko", "enforcements"): "исполнительные производства",
    ("checko", "inspections"): "надзорные проверки",
    ("checko", "contracts"): "государственные и регулируемые контракты",
    ("checko", "person"): "сведения о руководителях и учредителях",
    ("bo_nalog", "request"): "финансовая отчётность из ГИР БО (бесплатный ресурс ФНС)",
    ("rmsp", "request"): "реестр субъектов МСП (бесплатный источник ФНС)",
    ("egrul", "card"): "краткая карточка из сервиса ЕГРЮЛ (резерв)",
    ("apicloud", "fssp.php"): "исполнительные производства через резервный агрегатор",
    ("apicloud", "bankrot.php"): "сообщения о банкротстве через резервный агрегатор",
    ("apicloud", "kad_arbitr.php"): "арбитражные дела через резервный агрегатор",
    ("fedresurs", "publications"): "коммерческие сведения Федресурса: лизинг, залоги, факторинг, гарантии, СРО",
    ("fsa", "declarations"): "сертификаты и декларации соответствия (ФГИС Росаккредитации)",
    ("hh", "vacancies"): "вакансии и динамика найма (HeadHunter)",
    ("software_registry", "search"): "реестр отечественного ПО (Минцифры РФ)",
    ("site", "content"): "содержимое официального сайта и веб-стек",
    ("site", "dns"): "сетевая инфраструктура и DNS-записи",
    ("site", "ssl"): "криптографический сертификат безопасности SSL/TLS",
}

# Направления, которые система умеет, но запускает только по требованию.
# Их отсутствие — не отказ источника, а незапущенная проверка.
ON_DEMAND = {
    ("checko", "person"): "связи через руководителей и учредителей",
}

# Направления, которые опрашиваются бесплатно и всегда: их отсутствие
# в журнале — не отказ, а сбой бесплатного источника либо причина,
# по которой проверка не доходила до них.
FREE_ALWAYS = {
    ("bo_nalog", "request"): "финансовая история из ГИР БО",
    ("rmsp", "request"): "реестр МСП: независимое подтверждение масштаба",
    ("software_registry", "search"): "реестр отечественного ПО Минцифры",
}

# Направления, которых в системе пока нет вовсе. Перечисляются явно,
# чтобы их отсутствие не выглядело как отсутствие находок.
NOT_IMPLEMENTED = [
    ("публикации в СМИ и деловых изданиях",
     "веб-поиск не подключён, требуется доступ к поисковой службе"),
    ("детальный разбор сертификатов: изготовители за рубежом, ТН ВЭД, уведомления",
     "поиск ведётся только по заявителю и изготовителю, без детальных карточек"),
]


def _label(service: str, method: str) -> str:
    return MEANING.get((service, method)) or f"{service}/{method}"


def build_coverage(inn: str) -> CoverageReport:
    """Собрать отчёт о полноте проверки по идентификатору организации."""
    from osint_mcp.tools.query_guard import extract_inn_and_name
    parsed_inn, _ = extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    calls = ledger.calls_for(clean_inn)
    session = ledger.session_totals()
    daily = ledger.daily_totals()

    if not calls:
        # Пустой журнал — не «ничего не нашли», а «ничего не проверяли».
        # Без этой развилки отчёт читался бы как результат.
        return CoverageReport(
            inn=clean_inn,
            checked=False,
            gaps=[DataGap(
                what="проверка организации",
                kind="not_requested",
                reason=("По этому ИНН обращений не было. Возможно, организация "
                        "определялась по названию — тогда обращения записаны "
                        "отдельно. Сначала выполните проверку."),
            )],
            session_requests=session,
        )

    # ── расход по службам ────────────────────────────────────────────
    per_service: dict[str, ServiceUsage] = {}
    for call in calls:
        usage = per_service.setdefault(
            call.service,
            ServiceUsage(service=call.service, requests=0,
                         daily_spent=daily.get(call.service)),
        )
        usage.requests += 1
        setattr(usage, call.outcome, getattr(usage, call.outcome) + 1)

    # ── что получили и что не ответило ───────────────────────────────
    # Направление считается полученным, если хотя бы одно обращение к нему
    # вернуло данные: списочные методы опрашиваются постранично, и отказ
    # третьей страницы не отменяет первых двух.
    succeeded: dict[tuple[str, str], bool] = {}
    failures: dict[tuple[str, str], str | None] = {}
    for call in calls:
        key = (call.service, call.method)
        if call.outcome == "ok":
            succeeded[key] = True
        elif call.outcome == "empty":
            succeeded.setdefault(key, False)
        else:
            failures.setdefault(key, call.reason)

    obtained = [_label(*k) for k, got in succeeded.items() if got]
    empty = [k for k, got in succeeded.items() if not got]
    broken = [k for k in failures if not succeeded.get(k)]

    gaps: list[DataGap] = []
    for key in broken:
        gaps.append(DataGap(
            what=_label(*key),
            kind="source_failed",
            reason=failures.get(key) or "источник не ответил",
        ))
    for key in empty:
        gaps.append(DataGap(
            what=_label(*key),
            kind="no_data",
            reason="источник ответил, сведений по организации нет",
        ))
    for key, label in ON_DEMAND.items():
        if key not in succeeded and key not in failures:
            gaps.append(DataGap(
                what=label,
                kind="not_requested",
                reason="проверка не запускалась — вызовите check_affiliations",
            ))
    for key, label in FREE_ALWAYS.items():
        if key not in succeeded and key not in failures:
            gaps.append(DataGap(
                what=label,
                kind="not_requested",
                reason="бесплатный источник не опрашивался в этой сессии",
            ))
    for what, why in NOT_IMPLEMENTED:
        gaps.append(DataGap(what=what, kind="not_implemented", reason=why))

    report = CoverageReport(
        inn=clean_inn,
        checked=True,
        total_requests=len(calls),
        services=sorted(per_service.values(), key=lambda u: u.service),
        methods_ok=sorted({f"{s}/{m}" for (s, m), got in succeeded.items() if got}),
        methods_failed=sorted({f"{s}/{m}" for s, m in broken}),
        obtained=sorted(obtained),
        gaps=gaps,
        session_requests=session,
    )
    log.info("coverage", inn=inn, requests=len(calls),
             ok=len(report.methods_ok), failed=len(report.methods_failed))
    return report
