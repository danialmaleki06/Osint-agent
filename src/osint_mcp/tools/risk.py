"""Сводный сбор реестровых рисков.

Все проверки выполняются параллельно и возвращаются одним ответом.
Причина: каждое обращение агента к инструменту требует отдельного прогона
языковой модели, и пять последовательных вызовов обойдутся в пять прогонов —
это основная часть времени формирования досье, а не сами запросы к API.

Истолкования здесь нет: возвращаются исходные факты со ссылками.
Оценка риска вычисляется отдельно и детерминированно.
"""

import asyncio
from datetime import UTC

import structlog

from osint_mcp.context.apicloud import ApiCloudSource
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.fedresurs import FedresursSource
from osint_mcp.context.fsa import FsaSource
from osint_mcp.context.software_registry import SoftwareRegistrySource
from osint_mcp.models import ExtFact, Fact, RiskCollection, SourceResult
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.inn import validate_inn

log = structlog.get_logger()


async def collect_risk_facts(
    inn: str,
    source: CheckoSource | None = None,
    name: str | None = None,
) -> RiskCollection:
    """Опросить все реестровые источники параллельно."""
    # Проверки рисков доступны только по России. Для организаций Беларуси
    # и Казахстана источник данных не существует, и пустой результат
    # означал бы «нарушений нет» — это недопустимо.
    guess = detect_country(inn)
    if guess.country != "RU":
        return RiskCollection(
            inn=inn, results=[], sources_failed=0,
            coverage_note=(
                f"{guess.note} ПРОВЕРКА РИСКОВ НЕ ПРОВОДИЛАСЬ. "
                f"Не сообщай пользователю об отсутствии рисков — "
                f"источники по этой стране недоступны."
                if guess.note else
                "Идентификатор не опознан, проверка не выполнялась."
            ),
        )

    check = validate_inn(inn)
    if not check.valid:
        return RiskCollection(
            inn=inn, results=[],
            sources_failed=0,
            coverage_note=f"ИНН не прошёл проверку: {check.reason}. "
                          f"Проверка не выполнялась.",
        )

    src = source or CheckoSource()
    normalized = check.inn

    # Бесплатные официальные источники опрашиваются всегда: они не тратят
    # квоту платных справочников, а их отказ в проверку рисков не входит.
    # Федресурс — коммерческие сведения (лизинг, залоги, факторинг);
    # Росаккредитация — чем компания реально торгует.
    fedresurs = FedresursSource()
    fsa = FsaSource()
    software_reg = SoftwareRegistrySource()

    # return_exceptions=True принципиально: отказ одного источника
    # не должен обрывать сбор из остальных
    gathered = await asyncio.gather(
        src.check_registry_flags(normalized),
        src.check_arbitration(normalized),
        src.check_enforcement(normalized),
        src.check_inspections(normalized),
        src.check_procurement(normalized),
        fedresurs.check_commercial_facts(normalized),
        fsa.check_certificates(normalized, name),
        software_reg.check_software_registry(normalized),
        return_exceptions=True,
    )

    names = ["checko.registry_flags", "checko.arbitration", "checko.enforcement",
             "checko.inspections", "checko.procurement",
             "fedresurs.commercial", "fsa.certificates", "software_registry"]
    results: list[SourceResult] = []
    for src_name, item in zip(names, gathered):
        if isinstance(item, BaseException):
            results.append(SourceResult(
                source=src_name, status="unavailable",
                reason=f"Непредвиденная ошибка: {type(item).__name__}",
            ))
        else:
            results.append(item)

    facts: list[Fact] = [f for r in results for f in r.facts]

    notes: list[str] = []
    failed_results = [r for r in results if r.status not in ("ok", "partial")]
    if failed_results:
        broken = ", ".join(r.source for r in failed_results)
        notes.append(
            f"Недоступны источники: {broken}. Проверка НЕПОЛНАЯ. "
            f"Отсутствие находок по этим направлениям ничего не доказывает — "
            f"обязательно сообщи об этом пользователю."
        )
        # Резервный эшелон: агрегатор дёргается только когда прямой
        # источник отказал. Бесплатный тариф агрегатора (~200 запросов
        # в месяц) расходуется осознанно, а не впустую.
        backup = await _backup_checks(inn, failed_results, name)
        restored = [b for b in backup if b.status in ("ok", "partial")]
        results.extend(
            b for b in backup if b.source == "apicloud.enforcement" and b.status == "unavailable"
        )
        for b in restored:
            results.append(b)
            facts.extend(b.facts)
        if restored:
            notes.append(
                "Отказавшие направления продублированы резервным агрегатором "
                "(api-cloud): " + ", ".join(b.source for b in restored) +
                ". Найденные факты помечены как резервные."
            )
        else:
            notes.append(
                "Резервный агрегатор (api-cloud) недоступен либо ключ "
                "APICLOUD_KEY не задан — отказавшие направления не проверены."
            )

    # Счёт по НАПРАВЛЕНИЯМ, а не по записям: направление, целиком
    # восстановленное резервным источником, проверено — его прямой
    # отказ не считается. Банкротство резерва восстанавливает лишь часть
    # registry_flags (там ещё санкции и отметки ФНС), поэтому направление
    # считается проверенным только для приставов и арбитража.
    ok = sum(1 for r in results if r.status in ("ok", "partial"))
    restored_dirs = {
        b.source.split(".", 1)[1] for b in results
        if b.source.startswith("apicloud.") and b.status in ("ok", "partial")
    } & {"enforcement", "arbitration"}
    # Недоступный бесплатный источник — не «чистая проверка», но и не
    # провал платного канала: считается отдельно, в failure-логику
    # резервного эшелона не попадает.
    free_failed = sum(
        1 for r in results
        if r.status not in ("ok", "partial")
        and (r.source.startswith("fedresurs.") or r.source.startswith("fsa.") or r.source == "software_registry")
    )
    failed = sum(
        1 for r in results
        if r.status not in ("ok", "partial")
        and r.source.startswith("checko.")
        and r.source.split(".", 1)[1] not in restored_dirs
    ) + free_failed

    # Частичная выгрузка — не отказ, но и не полнота: у крупных организаций
    # записей десятки тысяч, разбивка строится по выборке
    # Причины неполноты у источников разные: где-то выборка вместо всей базы,
    # где-то приблизительный поиск. Обобщать их одной фразой нельзя —
    # получится неверно хотя бы для одного случая, поэтому перечисляем как есть.
    partial = [r for r in results if r.status == "partial" and r.reason]
    for r in partial:
        notes.append(f"[{r.source}] {r.reason}")

    note = " ".join(notes) or None

    log.info("collect_risk_facts", inn=normalized, facts=len(facts),
             ok=ok, failed=failed)

    return RiskCollection(inn=normalized, results=results, facts=facts,
                          sources_ok=ok, sources_failed=failed, coverage_note=note)


async def _backup_checks(
    inn: str, failed: list[SourceResult], name: str | None
) -> list[SourceResult]:
    """Резервные проверки через агрегатор — только по отказавшим направлениям.

    Каждое направление резервируется своим методом: приставы ищутся по ИНН,
    банкротство — по наименованию. Направления, которые прямой источник
    ответил частично (partial), резервом не дублируются: там данные есть,
    вопрос лишь в полноте выборки.
    """
    failed_sources = {r.source for r in failed if r.source.startswith("checko.")}
    if not failed_sources:
        return []

    backup = ApiCloudSource()
    tasks = []
    if "checko.enforcement" in failed_sources:
        tasks.append(backup.check_enforcement(inn))
    if "checko.arbitration" in failed_sources:
        tasks.append(backup.check_arbitration(inn))
    if "checko.registry_flags" in failed_sources:
        tasks.append(backup.check_bankruptcy(inn, name))

    if not tasks:
        return []
    log.info("backup_checks", inn=inn, directions=sorted(failed_sources))
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[SourceResult] = []
    for item in gathered:
        if isinstance(item, BaseException):
            out.append(SourceResult(
                source="apicloud", status="unavailable",
                reason=f"Ошибка резервного источника: {type(item).__name__}",
            ))
        else:
            out.append(item)
    return out



def extract_context_financial_risk_facts(ctx: "CompanyContext | None") -> list[Fact]:
    """Генерация риск-фактов по финансовым показателям карточки организации (отрицательные активы, налоговый долг)."""
    if ctx is None:
        return []
    from datetime import datetime

    facts: list[Fact] = []

    def _fmt_rub(val: float | None) -> str:
        if val is None:
            return "0 ₽"
        abs_v = abs(val)
        if abs_v >= 1_000_000_000:
            return f"{val / 1_000_000_000:.1f} млрд ₽"
        if abs_v >= 1_000_000:
            return f"{val / 1_000_000:.1f} млн ₽"
        if abs_v >= 1_000:
            return f"{val / 1_000:.0f} тыс. ₽"
        return f"{val:,.0f} ₽".replace(",", " ")

    # 0. Статус правоспособности в ЕГРЮЛ (ликвидация, прекращение, реорганизация, банкротство)
    if ctx.status:
        st_lower = ctx.status.lower()
        if any(w in st_lower for w in ("ликвид", "прекращ", "реорганиз", "исключ")):
            facts.append(
                ExtFact(
                    fact_id="CTX-STATUS-LIQUIDATED",
                    kind="registry_flag",
                    statement=f"Организация не действует: статус ЕГРЮЛ «{ctx.status}»",
                    source_url="https://egrul.nalog.ru/",
                    source_type="registry_api",
                    trust="registry",
                    retrieved_at=datetime.now(UTC),
                    payload={"status": ctx.status, "flag": "ликвидация"},
                )
            )
        elif "банкрот" in st_lower:
            facts.append(
                ExtFact(
                    fact_id="CTX-STATUS-BANKRUPT",
                    kind="bankruptcy",
                    statement=f"Процедура банкротства: статус ЕГРЮЛ «{ctx.status}»",
                    source_url="https://fedresurs.ru/",
                    source_type="registry_api",
                    trust="registry",
                    retrieved_at=datetime.now(UTC),
                    payload={"status": ctx.status, "Тип": "банкротство"},
                )
            )

    # 1. Отрицательные чистые активы (ст. 20 14-ФЗ)
    if ctx.fin_history:
        latest = ctx.fin_history[0]
        if latest.equity is not None and latest.equity < 0:
            facts.append(
                ExtFact(
                    fact_id="FIN-NEG-EQUITY",
                    kind="negative_net_assets",
                    statement=f"собственный капитал {_fmt_rub(latest.equity)} за {latest.year} г. (отрицательные чистые активы — признак банкротного состояния по ст. 20 14-ФЗ)",
                    source_url=latest.report_url or f"https://bo.nalog.gov.ru/organizations-card/{ctx.inn}",
                    source_type="registry_api",
                    trust="registry",
                    retrieved_at=datetime.now(UTC),
                    payload={"equity": latest.equity, "year": latest.year},
                )
            )

    # 2. Налоговая недоимка относительно масштаба бизнеса
    if ctx.extras and ctx.extras.tax_debt and ctx.extras.tax_debt >= 300_000:
        debt = ctx.extras.tax_debt
        latest = ctx.fin_history[0] if ctx.fin_history else None
        revenue = (latest.revenue if latest else None) or ctx.revenue_latest
        profit = latest.profit if latest else None

        scale_risk = False
        ratio_desc = ""
        if profit is not None and profit <= 0:
            scale_risk = True
            ratio_desc = f"при убыточном бизнесе (убыток {_fmt_rub(abs(profit))})"
        elif profit is not None and profit > 0 and (debt / profit) > 0.5:
            scale_risk = True
            ratio_desc = f"составляет {(debt / profit):.0%} от годовой чистой прибыли"
        elif revenue is not None and revenue > 0 and (debt / revenue) > 0.05:
            scale_risk = True
            ratio_desc = f"составляет {(debt / revenue):.1%} от годовой выручки"
        elif (revenue is None or revenue == 0) and debt >= 10_000_000:
            scale_risk = True
            ratio_desc = "крупная сумма недоимки перед бюджетом"

        if scale_risk:
            facts.append(
                ExtFact(
                    fact_id="FIN-TAX-DEBT-SCALE",
                    kind="tax_debt_scale_risk",
                    statement=f"задолженность по налогам {_fmt_rub(debt)} {ratio_desc} (риск приостановки операций по счетам по ст. 76 НК РФ)",
                    source_url=f"https://service.nalog.ru/zd.do?inn={ctx.inn}",
                    source_type="registry_api",
                    trust="registry",
                    retrieved_at=datetime.now(UTC),
                    payload={"tax_debt": debt, "revenue": revenue, "profit": profit},
                )
            )

    return facts
