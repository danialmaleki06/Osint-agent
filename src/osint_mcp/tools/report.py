"""Отчёт по организации: объём данных зависит от запроса.

Три режима:
  brief — карточка + вердикт: то, что менеджер читает перед решением;
  full  — всё, что система вообще собрала, включая детали карточки,
          финансовую историю, налоги, события истории;
  batch — список ИНН одним ответом, кратко по каждому: беглая разведка
          перед тем, как тратить квоту на полную проверку.

Полный режим НЕ запрашивает новых источников поверх штатного прогона:
collect_risk_facts и карточка опрашивают те же службы, что и раньше.
Разница режимов — в том, сколько собранного доходит до пользователя.

Прямые ссылки на первоисточники (PDF отчётностей ФНС, карточки реестров)
в отчёты не входят: они собираются всегда, но отдаются дозапросом
get_company_links — иначе отчёт разбухает там, где пользователю нужны
только выводы. Пользователь попросил подтвердить цифры — агент запрашивает
ссылки отдельно.
"""

from datetime import date, datetime, timedelta, timezone

from osint_mcp.models import CompanyContext, FinancialYear, RiskCollection
from osint_mcp.config import settings
from osint_mcp.scoring.models import ScoreResult
from osint_mcp.tools.sales_intelligence import build_sales_intelligence as _build_sales_intelligence
from osint_mcp.tools.statutory_hr import build_statutory_hr_profile as _build_statutory_hr
from osint_mcp.tools.affiliations_lite import build_affiliations_lite as _build_affiliations_lite

# Порог «крупная компания» для массового адреса: у крупного бизнеса
# регистрация по адресу с другими организациями — норма (бизнес-центры),
# и упоминать её как риск — ошибка.
_MASS_ADDRESS_MAX_SIZE = "small"

_SIZE_ORDER = {"micro": 0, "small": 1, "medium": 2, "large": 3}


def _fmt_amount(value: float | None) -> str:
    if value is None:
        return "нет данных"
    v = float(value)
    if v >= 1_000_000_000:
        return f"{v / 1_000_000_000:.1f} млрд ₽"
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f} млн ₽"
    if v >= 1_000:
        return f"{v / 1_000:.0f} тыс ₽"
    return f"{v:.0f} ₽"


def _fmt_date(value: date | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    return value.isoformat()


def _size_rank(category: str | None) -> int:
    return _SIZE_ORDER.get(category or "unknown", 1)


def _relevant_mass_address(ctx: CompanyContext) -> list[str]:
    """Массовый адрес, отфильтрованный по масштабу.

    Для микро/малого бизнеса признак решает, для крупного неприменим.
    None-масштаб считаем малым: неизвестность не должна прятать признак.
    """
    extras = ctx.extras
    if not extras or not extras.mass_address_orgs:
        return []
    if _size_rank(ctx.size_category) > _SIZE_ORDER[_MASS_ADDRESS_MAX_SIZE]:
        return []
    return extras.mass_address_orgs


def _debt_lines(y: "FinancialYear") -> list[str]:
    """Платёжеспособность словами: соотношения важнее абсолютных сумм.

    Долг против ВЫРУЧКИ ничего не говорит — расплачиваются из прибыли.
    Смысленные метрики:
      * долг / чистая прибыль — сколько лет зарабатывать на закрытие
        долга (тревога от 3 лет);
      * (деньги + дебиторка) / краткосрочные долги — можно ли гасить
        текущие обязательства без продажи имущества (тревога ниже 1);
      * займы при отрицательном капитале — покрывать нечем.
    Рост кредиторки над дебиторкой сам по себе НЕ тревога: торговый
    кредит поставщиков финансирует растущий бизнес. Пустые строки
    (None) — источник не отдал, нули — «не привлекали».
    """
    lines: list[str] = []
    total_debt = (y.loans or 0.0) + (y.short_debt or 0.0) if (
        y.loans is not None or y.short_debt is not None) else None
    if total_debt is not None and total_debt > 0:
        lines.append(f"обязательства всего: {_fmt_amount(total_debt)}")
        # Долг измеряем прибылью, а не выручкой: расплачиваются из заработанного
        if y.profit is not None and y.profit > 0:
            years_to_repaid = total_debt / y.profit
            if years_to_repaid >= 3:
                lines.append(
                    f"долг равен {years_to_repaid:.0f} годам прибыли — "
                    "высокая долговая нагрузка"
                )
        if y.equity is not None and y.equity < 0:
            lines.append("обязательства при отрицательном капитале — "
                         "долги покрываются только выручкой, положение критическое")
    # Ликвидность: чем гасить текущие долги, если кредиторы придут разом
    if y.short_debt and y.short_debt > 0:
        liquid = (y.cash or 0.0) + (y.receivables or 0.0)
        coverage = liquid / y.short_debt
        if coverage < 1:
            lines.append(
                f"краткосрочные долги {_fmt_amount(y.short_debt)} превышают "
                f"ликвидные активы (деньги + дебиторка) {_fmt_amount(liquid)} — "
                "платёжеспособность зависит от непрерывного потока выручки"
            )
    if y.receivables and y.assets:
        share = y.receivables / y.assets
        if share >= 0.6:
            lines.append(
                f"дебиторская задолженность {_fmt_amount(y.receivables)} — "
                f"{share * 100:.0f}% активов: деньги заморожены в чужих долгах"
            )
    return lines


def _capital_cushion(ctx: CompanyContext) -> str | None:
    """Уставный капитал против обязательств: чем прикрываться при беде.

    Минимальный капитал при больших долгах — норма для малого бизнеса,
    но читателю важно понимать: гарантий у компании почти нет, кредитор
    получит только то, что заработает она сама. Даю наравне с долговой
    нагрузкой — это вторая половина ответа на «сможет расплатиться».
    """
    if ctx.capital is None:
        return None
    years = ctx.fin_history or []
    short_debt = next((y.short_debt for y in years if y.short_debt), None) if years else None
    if not short_debt or short_debt <= 0:
        return None
    cover = short_debt / ctx.capital if ctx.capital > 0 else None
    if cover is None or cover < 50:
        return None
    return (
        f"уставный капитал {_fmt_amount(ctx.capital)} покрывает менее "
        f"{_fmt_amount(1 / cover * short_debt)} краткосрочных обязательств "
        f"({_fmt_amount(short_debt)}) — при беде кредитор получит только заработанное"
    )




# ───────────────────  Лицензии: категоризация по регуляторам  ───────────────────

_LICENSE_CATEGORIES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("фсб", "криптограф", "шифрован", "государственной тайны", "гостайн"), "ФСБ (Криптография / Защита гостайны)"),
    (("фстэк", "конфиденциальн", "кии", "средств защиты информации", "технической защиты"), "ФСТЭК (Защита конфиденциальной информации / КИИ)"),
    (("роскомнадзор", "минкомсвяз", "минцифр", "связ", "телематическ", "передач"), "Роскомнадзор (Связь и телематика)"),
    (("мчс", "пожарн", "огнезащит", "тушени"), "МЧС (Пожарная безопасность)"),
    (("минкульт", "культурного наследия", "реставрац", "памятник"), "Минкультуры (Реставрация памятников культуры)"),
    (("росздравнадзор", "минздрав", "медицинск", "фармацевтическ"), "Росздравнадзор (Медицина и фармацевтика)"),
    (("ростехнадзор", "промышленной безопасности", "маркшейдер", "опасных производств"), "Ростехнадзор (Промбезопасность)"),
    (("образован", "учебн"), "Минобрнауки (Образовательная деятельность)"),
)


def _classify_license(lic) -> str:
    text = f"{getattr(lic, 'issuer', '') or ''} {getattr(lic, 'activity', '') or ''} {getattr(lic, 'number', '') or ''}".lower()
    for needles, cat in _LICENSE_CATEGORIES:
        if any(n in text for n in needles):
            return cat
    return "Отраслевая государственная лицензия"


_CATEGORY_DESCRIPTIONS = {
    "ФСБ (криптография и защита гостайны)": "Разрешение на работу с шифровальными средствами и защиту гостайны",
    "ФСТЭК (техническая защита конфиденциальной информации)": "Право на защиту конфиденциальных данных и аттестацию информационных систем",
    "Роскомнадзор / Минцифры (связь, телематика и СМИ)": "Лицензия оператора связи, телематических служб или медиа",
    "МЧС (пожарная безопасность)": "Монтаж, техобслуживание и ремонт систем пожарной безопасности",
    "Минкультуры (реставрация объектов культурного наследия)": "Работы по сохранению объектов культурного наследия",
    "Росздравнадзор (медицина и фармацевтика)": "Медицинская или фармацевтическая деятельность",
    "Ростехнадзор (промышленная безопасность)": "Эксплуатация взрывопожароопасных и опасных производственных объектов",
    "Образовательная деятельность": "Официальная образовательная деятельность и выдача дипломов/сертификатов",
}


def _build_license_breakdown(licenses: list) -> dict | None:
    if not licenses:
        return None
    groups: dict[str, list[dict]] = {}
    for lic in licenses:
        cat = _classify_license(lic)
        entry = {
            "номер": lic.number,
            **({"орган": lic.issuer} if lic.issuer else {}),
            **({"деятельность": lic.activity} if lic.activity else {}),
            **({"дата": lic.issued_at.isoformat()} if lic.issued_at else {}),
        }
        groups.setdefault(cat, []).append(entry)
    summary_lines = [f"{cat}: {len(items)}" for cat, items in groups.items()]
    explanations = [
        f"{cat} — {_CATEGORY_DESCRIPTIONS.get(cat, 'Отраслевое лицензирование')}"
        for cat in groups.keys()
    ]
    return {
        "всего": len(licenses),
        "по_категориям": summary_lines,
        "расшифровка_смысла": explanations,
        "детализация": groups,
    }


# ───────────────────  Матрица финансового здоровья  ───────────────────

def _build_financial_health_matrix(ctx: CompanyContext) -> dict | None:
    """Сводная матрица финансового здоровья: рентабельность ROS, динамика, чистые активы, соразмерность налогов."""
    if not ctx.fin_history and not (ctx.extras and ctx.extras.tax_debt):
        return None

    matrix: dict = {}
    years = ctx.fin_history
    if years:
        latest = years[0]
        # 1. Рентабельность продаж (ROS)
        if latest.revenue and latest.revenue > 0 and latest.profit is not None:
            ros = (latest.profit / latest.revenue) * 100.0
            if ros >= 20.0:
                ros_status = "🟢 Высокая рентабельность бизнеса"
            elif ros >= 5.0:
                ros_status = "🟢 Стандартная операционная рентабельность"
            elif ros >= 0.0:
                ros_status = "🟡 Низкая маржинальность (чувствительность к издержкам)"
            else:
                ros_status = "🟠 Отрицательная рентабельность (операционный убыток)"
            matrix["рентабельность_продаж_ros"] = {
                "значение_процент": round(ros, 1),
                "оценка": ros_status,
                "пояснение_простыми_словами": (
                    f"С каждых 100 ₽ выручки чистыми остаётся {ros:.0f} ₽."
                    if ros >= 0 else "Бизнес работает с чистым убытком."
                ),
                "выручка": _fmt_amount(latest.revenue),
                "чистая_прибыль": _fmt_amount(latest.profit),
            }

        # 2. Динамика выручки год к году (YoY)
        if len(years) >= 2:
            prev = next((y for y in years[1:] if y.revenue is not None and y.revenue > 0), None)
            if prev and latest.revenue is not None:
                growth_pct = ((latest.revenue - prev.revenue) / prev.revenue) * 100.0
                growth_label = "🟢 Рост оборота" if growth_pct > 0 else "🟠 Сжатие выручки"
                matrix["динамика_выручки_yoy"] = {
                    "темп_прироста_процент": round(growth_pct, 1),
                    "период": f"{prev.year} → {latest.year}",
                    "оценка": f"{growth_label} ({growth_pct:+.1f}%)",
                    "пояснение_простыми_словами": (
                        f"Выручка выросла на {growth_pct:.0f}% к прошлому году."
                        if growth_pct > 0 else f"Выручка упала на {abs(growth_pct):.0f}% к прошлому году."
                    ),
                }

        # 3. Чистые активы (собственный капитал)
        if latest.equity is not None:
            is_negative = latest.equity < 0
            matrix["чистые_активы"] = {
                "сумма": _fmt_amount(latest.equity),
                "статус": "⛔ Отрицательные чистые активы (риск ликвидации ст. 20 14-ФЗ)" if is_negative else "🟢 Капитал в норме",
                "пояснение_простыми_словами": (
                    "Долги превышают стоимость всего имущества (высокий риск банкротства)."
                    if is_negative else "Собственный капитал положителен: имущество и активы превышают долги."
                ),
                "критично": is_negative,
            }

    # 4. Налоговая нагрузка и соразмерность недоимки
    if ctx.extras and ctx.extras.tax_debt:
        debt = ctx.extras.tax_debt
        matrix["налоговая_задолженность"] = {
            "сумма": _fmt_amount(debt),
        }
        if years and years[0].profit is not None and years[0].profit > 0:
            ratio = (debt / years[0].profit) * 100.0
            matrix["налоговая_задолженность"]["доля_к_годовой_прибыли_процент"] = round(ratio, 1)
            if ratio > 50.0:
                matrix["налоговая_задолженность"]["оценка"] = "🟠 Высокий риск блокировки счетов (долг >50% чистой прибыли)"
            else:
                matrix["налоговая_задолженность"]["оценка"] = "🟡 Умеренная текущая недоимка"
        elif years and years[0].revenue and years[0].revenue > 0:
            ratio_rev = (debt / years[0].revenue) * 100.0
            matrix["налоговая_задолженность"]["доля_к_выручке_процент"] = round(ratio_rev, 2)

    return matrix or None


# ───────────────────  Цифровой контур и стек (Digital Footprint)  ───────────────────

def _build_digital_footprint(ctx: CompanyContext) -> dict | None:
    """Блок цифрового контура: только значимые сигналы (CMS, CRM, аналитика с ID, SSL, возраст домена).

    Отфильтровывает тривиальный шум вроде 'HTML' или 'CSS'.
    """
    fp: dict = {}
    site_url = ctx.brand_domain or (ctx.extras.contacts.website if ctx.extras and ctx.extras.contacts else None)
    if site_url:
        fp["сайт"] = site_url

    if ctx.domain_created_at:
        age_years = (date.today() - ctx.domain_created_at).days / 365.25
        fp["возраст_домена"] = f"{int(age_years)} лет (с {ctx.domain_created_at.strftime('%d.%m.%Y')})"

    if ctx.ssl_info:
        ssl_val = "🟢 Действителен" if ctx.ssl_info.valid else "⛔ Недействителен / истёк"
        bits = [ssl_val]
        if ctx.ssl_info.issuer:
            bits.append(f"эмитент: {ctx.ssl_info.issuer}")
        if ctx.ssl_info.days_left is not None:
            bits.append(f"осталось {ctx.ssl_info.days_left} дн.")
        fp["ssl_сертификат"] = ", ".join(bits)

    tech = ctx.site_tech
    if tech:
        # CMS/платформа: фильтруем тривиальные заглушки
        cms_clean = [c for c in tech.cms if c.lower() not in ("html", "html5", "css", "css3", "javascript", "jquery")]
        if cms_clean:
            fp["платформа_cms"] = cms_clean

        crm_list = getattr(tech, "crm_widgets", None) or getattr(tech, "crm", None)
        if crm_list:
            fp["crm_и_виджеты"] = crm_list

        # Аналитика с конкретными номерами счётчиков (критично для выявления аффилированных сетей)
        analytics_items = []
        tr_dict = getattr(tech, "tracker_ids", None) or getattr(tech, "trackers", None)
        if tr_dict:
            for k, ids in tr_dict.items():
                label = "Яндекс.Метрика" if "yandex" in k else ("Google Analytics" if "google" in k else k)
                analytics_items.append(f"{label} (ID: {', '.join(ids[:3])})")
        elif tech.analytics:
            analytics_items = [a for a in tech.analytics if a.lower() not in ("html", "meta")]
        if analytics_items:
            fp["аналитика_и_трекеры"] = analytics_items

    # Корпоративная почта
    if ctx.extras and ctx.extras.contacts and ctx.extras.contacts.emails:
        domains = set()
        for em in ctx.extras.contacts.emails:
            if "@" in em:
                domains.add(em.split("@", 1)[1].lower())
        if domains:
            fp["доменная_почта"] = sorted(domains)

    return fp or None


def _digital_footprint_lines(ctx: CompanyContext) -> list[str]:
    """Строки цифрового следа для секции полного отчёта."""
    fp = _build_digital_footprint(ctx)
    if not fp:
        return []
    lines = []
    if fp.get("сайт"):
        age_str = f" ({fp.get('возраст_домена')})" if fp.get("возраст_домена") else ""
        lines.append(f"домен: {fp['сайт']}{age_str}")
    if fp.get("платформа_cms"):
        lines.append("платформа / CMS: " + ", ".join(fp["платформа_cms"]))
    if fp.get("crm_и_виджеты"):
        lines.append("клиентские виджеты / CRM: " + ", ".join(fp["crm_и_виджеты"]))
    if fp.get("аналитика_и_трекеры"):
        lines.append("веб-аналитика: " + "; ".join(fp["аналитика_и_трекеры"]))
    if fp.get("ssl_сертификат"):
        lines.append(f"SSL: {fp['ssl_сертификат']}")
    if fp.get("доменная_почта"):
        lines.append("корпоративная почта: " + ", ".join(fp["доменная_почта"]))
    return lines


def _fin_lines(ctx: CompanyContext) -> list[str]:
    """Динамика финансов словами: то, что не видно из одного числа.

    Пустая история — не «финансов нет»: означает, что отчётности
    не сданы или источник не ответил; различать их обязан reason сборки.
    """
    lines: list[str] = []
    years = ctx.fin_history
    if years:
        latest = years[0]
        parts = [f"{latest.year}: выручка {_fmt_amount(latest.revenue)}"]
        if latest.profit is not None:
            sign = "прибыль" if latest.profit >= 0 else "убыток"
            parts.append(f"{sign} {_fmt_amount(abs(latest.profit))}")
        if latest.equity is not None and latest.equity < 0:
            parts.append(f"собственный капитал {_fmt_amount(latest.equity)} (отрицательный)")
        lines.append("; ".join(parts))
        if len(years) >= 2:
            prev = next((y for y in years[1:] if y.revenue is not None), None)
            if prev and prev.revenue and latest.revenue is not None:
                ratio = latest.revenue / prev.revenue
                if ratio <= 0.5:
                    lines.append(
                        f"выручка упала более чем вдвое: {_fmt_amount(prev.revenue)} "
                        f"({prev.year}) → {_fmt_amount(latest.revenue)} ({latest.year})"
                    )
                elif ratio >= 2.0:
                    lines.append(
                        f"выручка выросла более чем вдвое: {_fmt_amount(prev.revenue)} "
                        f"({prev.year}) → {_fmt_amount(latest.revenue)} ({latest.year})"
                    )
        debt = _debt_lines(latest)
        lines.extend(debt)
    cushion = _capital_cushion(ctx)
    if cushion:
        lines.append(cushion)
    if ctx.extras:
        e = ctx.extras
        bits = []
        if e.tax_debt:
            bits.append(f"задолженность по налогам {_fmt_amount(e.tax_debt)}")
        if e.tax_paid_total is not None:
            bits.append(f"уплачено налогов за {e.tax_year or '—'}: {_fmt_amount(e.tax_paid_total)}")
        if e.tax_mode:
            bits.append("режим: " + ", ".join(e.tax_mode))
        if bits:
            lines.append("; ".join(bits))
    return lines


def _extras_lines(ctx: CompanyContext) -> list[str]:
    """Детали карточки, важные для решения, одной строкой каждое."""
    lines: list[str] = []
    extras = ctx.extras
    if not extras:
        return lines
    if extras.address_unreliable:
        lines.append("адрес признан ФНС недостоверным")
    mass = _relevant_mass_address(ctx)
    if mass:
        lines.append(
            f"по адресу зарегистрировано ещё организаций: {len(mass)} "
            "(признак массового адреса)"
        )
    if extras.licenses:
        cat_counts: dict[str, int] = {}
        for lic in extras.licenses:
            cat = _classify_license(lic)
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        cat_summary = ", ".join(f"{cat} ({cnt})" for cat, cnt in cat_counts.items())
        names = "; ".join(
            f"{lic.number}{f' ({lic.activity})' if lic.activity else ''}"
            for lic in extras.licenses[:3]
        )
        more = f" и ещё {len(extras.licenses) - 3}" if len(extras.licenses) > 3 else ""
        lines.append(f"лицензии ({len(extras.licenses)} шт.): {cat_summary} — {names}{more}")
    contacts = extras.contacts
    if contacts:
        bits = []
        if contacts.website:
            bits.append(f"сайт {contacts.website}")
        if contacts.emails:
            bits.append("почта " + ", ".join(contacts.emails[:3]))
        if contacts.phones:
            bits.append("тел. " + ", ".join(contacts.phones[:3]))
        if bits:
            lines.append("; ".join(bits))
    return lines


def _event_lines(ctx: CompanyContext) -> list[str]:
    """События истории — кратко, свежие первыми."""
    if not ctx.events:
        return []
    lines = []
    for ev in sorted(ctx.events, key=lambda e: e.event_date or date.min, reverse=True)[:10]:
        lines.append(f"{ev.event_date.isoformat() if ev.event_date else '—'}: {ev.event}")
    return lines


def _management_turnover_line(ctx: CompanyContext) -> str | None:
    """Частая смена руководителя — перетасовка управления.

    Единичная смена — норма. Три и больше за пять лет — повод спросить
    почему ДО сделки: у массовых директоров так выглядит передача
    компании под новые долги, у проблемных — ротация перед крахом.
    """
    cutoff = date.today() - timedelta(days=5 * 365)
    changes = [
        ev for ev in ctx.events
        if ev.event_date and ev.event_date >= cutoff
        and ev.event and "руковод" in ev.event.lower()
    ]
    if len(changes) < 3:
        return None
    return (
        f"смен руководителя за последние 5 лет: {len(changes)} — "
        "управление перетасовывается, выясни причины до сделки"
    )


def _margin_lines(ctx: CompanyContext) -> list[str]:
    """Тренд маржи: тающая прибыльность видна раньше долгов.

    Маржа (прибыль/выручка) падает два года подряд при суммарном
    проседании от 5 п.п. — демпинг, рост затрат или потеря рынка.
    Разовое падение и болтанка в пределах полпункта шумом не считаются:
    ложная тревога дороже молчания.
    """
    points = [
        (y.year, y.profit / y.revenue * 100)
        for y in ctx.fin_history
        if y.revenue and y.revenue > 0 and y.profit is not None
    ]
    if len(points) < 3:
        return []
    points.sort(key=lambda t: t[0])  # старые первыми
    trailing_drops = 0
    for (_, m1), (_, m2) in zip(points, points[1:]):
        trailing_drops = trailing_drops + 1 if m2 < m1 - 0.5 else 0
    total_decline = points[0][1] - points[-1][1]
    if trailing_drops < 2 or total_decline < 5.0:
        return []
    y0, m0 = points[0]
    y1, m1 = points[-1]
    return [
        f"маржа тает {trailing_drops} года подряд: {m0:.0f}% ({y0}) → {m1:.0f}% ({y1}) — "
        "демпинг, рост затрат или потеря рынка; выясни причину до сделки"
    ]


def _productivity_line(ctx: CompanyContext) -> str | None:
    """Выручка на сотрудника — нейтральная мера эффективности.

    Наивная «зарплатоёмкость» (налоги/численность) врёт: в налоги
    попадают не только зарплатные взносы. Выручка на сотрудника честно
    описывает масштаб бизнеса на одного человека и ничего не утверждает.
    """
    if ctx.employees is None or not ctx.fin_history:
        return None
    latest = ctx.fin_history[0]
    if not latest.revenue or latest.revenue < 10_000_000 or ctx.employees < 5:
        return None
    per = latest.revenue / ctx.employees
    return f"выручка на сотрудника: ~{_fmt_amount(per)} ({ctx.employees} чел.)"


def _gov_share_line(risk: RiskCollection | None, ctx: CompanyContext) -> str | None:
    """Доля госконтрактов в выручке — зависимость от бюджета.

    Суммы исполненных контрактов 44/223-ФЗ против последней выручки.
    Существенная доля — политический и платёжный риск: секвестры,
    казначейские паузы. Считается только при достаточной выборке:
    меньше трёх контрактов — не система, а случайность.
    """
    if risk is None:
        return None
    procs = [r.procurement for r in risk.results if r.procurement is not None]
    if not procs:
        return None
    sup = procs[0].as_supplier
    if sup.count < 3:
        return None
    rev = ctx.revenue_latest or (ctx.fin_history[0].revenue if ctx.fin_history else None)
    if not rev or rev < 10_000_000:
        return None
    share = sup.total_amount / rev
    base = (f"госконтракты ≈ {share:.0%} последней выручки "
            f"({sup.count} контрактов на {_fmt_amount(sup.total_amount)})")
    if share >= 0.3:
        return base + " — зависимость от бюджета: секвестры и задержки платежей бьют напрямую"
    if share >= 0.1:
        return base
    return None


def _rename_line(ctx: CompanyContext) -> str | None:
    """«Смена вывески» — подсказка, где искать прошлое организации."""
    if not ctx.former_names:
        return None
    return (
        f"переименований: {len(ctx.former_names)} (например, {ctx.former_names[0]}) — "
        "публикации, суды и отзывы ищи и по прежним именам"
    )


def _sales_lines(ctx: CompanyContext, risk: RiskCollection | None = None) -> list[str]:
    """Коммерческие сигналы: чем жива компания и когда с ней говорить.

    Это не риски, а окна возможностей для продаж и анализа направления:
    вакансии показывают потребности, новые ОКВЭДы — расширение,
    события истории — момент перестройки (смена директора часто
    пересматривает подрядчиков). Нейтрально к вердикту, в краткий
    отчёт не входит: ради этого просят «подробно».
    """
    lines: list[str] = []
    extras = ctx.extras
    if extras and extras.okved_extra:
        lines.append("доп. ОКВЭДы (чем занимается фактически): "
                     + "; ".join(extras.okved_extra[:5]))
    if extras and extras.trademarks:
        lines.append("товарные знаки: " + ", ".join(extras.trademarks[:5]))
    if ctx.software_products:
        prods = "; ".join(f"«{p.name}» (№{p.reg_number or 'б/н'})" for p in ctx.software_products[:4])
        lines.append(f"реестр отечественного ПО Минцифры: {prods} — льгота по НДС и приоритет в госзакупках")
    hiring = ctx.hiring
    if hiring is not None:
        if hiring.open_vacancies:
            roles = "; ".join(hiring.roles[:5])
            more = (f" и ещё {hiring.open_vacancies - len(hiring.roles[:5])}"
                    if hiring.open_vacancies > len(hiring.roles[:5]) else "")
            caveat = " (совпадение по имени — уточнить принадлежность)" if hiring.found_by_name else ""
            lines.append(f"открытые вакансии: {hiring.open_vacancies}{caveat}: {roles}{more}")
            if hiring.leadership_roles:
                lines.append("окно входа для B2B (найм руководства): " + "; ".join(hiring.leadership_roles[:3]))
            if hiring.tech_stack:
                lines.append("внутренний софт и стек (из вакансий): " + ", ".join(hiring.tech_stack))
            if hiring.it_investing:
                lines.append("инвестиции в IT/R&D: компания активно нанимает инженерные и продуктовые кадры")
        elif hiring.reason:
            lines.append(f"найм не проверен: {hiring.reason}")
        else:
            lines.append("открытых вакансий не найдено")
    if ctx.site_tech:
        tech_items = []
        if ctx.site_tech.cms:
            tech_items.append("CMS: " + ", ".join(ctx.site_tech.cms))
        if ctx.site_tech.crm_widgets:
            tech_items.append("CRM/виджеты: " + ", ".join(ctx.site_tech.crm_widgets))
        if ctx.site_tech.analytics:
            tech_items.append("аналитика: " + ", ".join(ctx.site_tech.analytics))
        if tech_items:
            lines.append("стек сайта: " + "; ".join(tech_items))
    if ctx.ssl_info:
        if ctx.ssl_info.days_left is not None and ctx.ssl_info.days_left <= 14:
            lines.append(f"внимание к сайту: SSL-сертификат истекает через {ctx.ssl_info.days_left} дн. (риск сбоя)")
        elif ctx.ssl_info.valid:
            lines.append(f"SSL-сертификат: валиден (эмитент: {ctx.ssl_info.issuer or 'доверенный ЦС'})")
    if risk is not None:
        for res in risk.results:
            if res.inspections and res.inspections.planned_inspections:
                for pi in res.inspections.planned_inspections[:3]:
                    d = pi.date_start.isoformat() if pi.date_start else "дата уточняется"
                    lines.append(
                        f"предстоящая проверка ЕРКНМ: {pi.authority} (с {d})"
                        + (f", тип: {pi.inspection_type}" if pi.inspection_type else "")
                        + " — окно для предложения услуг аудита, охраны труда и безопасности"
                    )
    if ctx.events:
        fresh = [ev for ev in ctx.events
                 if ev.event_date and ev.event_date >= date.today() - timedelta(days=365)]
        for ev in sorted(fresh, key=lambda e: e.event_date, reverse=True)[:3]:
            lines.append(f"окно входа — {ev.event_date.isoformat()}: {ev.event}")
    return lines


def _full_sections(ctx: CompanyContext | None, risk: RiskCollection | None) -> list[dict]:
    """Секции полного отчёта, которых нет в кратком."""
    if ctx is None:
        return []
    sections: list[dict] = []
    fin = _fin_lines(ctx)
    margin = _margin_lines(ctx)
    if margin:
        fin = (fin or []) + margin
    if fin:
        sections.append({"название": "финансы и налоги", "пункты": fin})
    profile = _profile_lines(ctx)
    if profile:
        sections.insert(0, {"название": "профиль деятельности", "пункты": profile})
    extras = _extras_lines(ctx)
    if extras:
        sections.append({"название": "лицензии, контакты, адрес", "пункты": extras})
    events = _event_lines(ctx)
    turnover = _management_turnover_line(ctx)
    if turnover:
        events = (events or []) + [turnover]
    if events:
        sections.append({"название": "существенные события истории", "пункты": events})
    sales = _sales_lines(ctx, risk)
    gov = _gov_share_line(risk, ctx)
    if gov:
        sales = (sales or []) + [gov]
    if sales:
        sections.append({"название": "коммерческие сигналы", "пункты": sales})
    creditor = _plaintiff_lines(risk)
    if creditor:
        sections.append({"название": "платёжный климат", "пункты": creditor})
    commercial = _commercial_lines(risk)
    if commercial:
        sections.append({"название": "коммерческая активность", "пункты": commercial})
    fp_lines = _digital_footprint_lines(ctx)
    if fp_lines:
        sections.append({"название": "цифровой контур и стек", "пункты": fp_lines})
    return sections


def _context_lines(ctx: CompanyContext) -> list[str]:
    """Общая часть краткого и полного отчёта: карточка по-человечески."""
    lines: list[str] = []
    if ctx.status and ctx.status != "Действует":
        lines.append(f"статус: {ctx.status}")
    okved = ctx.okved_text or (ctx.okved_code and f"ОКВЭД {ctx.okved_code}")
    if okved:
        lines.append(f"деятельность: {okved}")
    bits = []
    if ctx.employees is not None:
        bits.append(f"{ctx.employees} чел.")
    if ctx.revenue_latest is not None:
        bits.append(f"выручка {_fmt_amount(ctx.revenue_latest)}")
    if bits:
        lines.append("масштаб: " + ", ".join(bits))
    if ctx.registered_at:
        lines.append(f"зарегистрирована {_fmt_date(ctx.registered_at)}")
    if ctx.director_fio:
        lines.append(f"руководитель: {ctx.director_fio}")
    if ctx.former_names:
        lines.append("прежние наименования: " + "; ".join(ctx.former_names))
    return lines


_MODEL_LABEL = {
    "product": "продуктовая компания (свой продукт и товарные знаки)",
    "outsourced": "подряд/аутсорс (работы по заказу клиентов)",
    "retail": "розница/услуги населению",
}
_STAGE_LABEL = {
    "young": "ранняя стадия (до 3 лет) — устойчивость не набрана, проверяй капитал",
    "growth": "растущая (выручка растёт или активный найм) — окно входа",
    "mature": "зрелая (8+ лет) — история устойчивости набрана",
    "shrinking": "сжимается (нет найма, выручка не растёт) — уточни причины",
}


def _profile_lines(ctx: CompanyContext) -> list[str]:
    """Краткий разбор профиля: чем занята, на чём держится, на какой стадии.

    Эвристики по модели и стадии — не факты: строка написана осторожно,
    с подсказкой, что проверять дальше. None не выводится: догадку
    не выдаём за разбор.
    """
    lines: list[str] = []
    if ctx.business_model:
        lines.append("модель: " + _MODEL_LABEL[ctx.business_model])
    if ctx.business_stage:
        lines.append("стадия: " + _STAGE_LABEL[ctx.business_stage])
    if ctx.site_self_description:
        lines.append(f"о себе: «{ctx.site_self_description}» (с сайта компании)")
    # Эффективность и смена вывески самостоятельны: добавляются даже когда
    # модель/стадия не определились — иначе профиль молчит там, где есть
    # что сказать
    productivity = _productivity_line(ctx)
    if productivity:
        lines.append(productivity)
    rename = _rename_line(ctx)
    if rename:
        lines.append(rename)
    if not lines:
        return lines
    # Домен младше бизнеса — перерегистрация: живой бизнес переписали
    # на новое юрлицо. Не приговор (бывает и легитимная реструктуризация),
    # но вопрос об истории компании обязателен до сделки.
    if ctx.domain_created_at and ctx.registered_at:
        company_age = (date.today() - ctx.registered_at).days / 365.25
        domain_age_years = (date.today() - ctx.domain_created_at).days / 365.25
        if domain_age_years < company_age * 0.4 and company_age - domain_age_years >= 3:
            lines.append(
                f"домен создан {ctx.domain_created_at.isoformat()} при регистрации "
                f"юридического лица {ctx.registered_at.isoformat()} — "
                "юридическое лицо моложе бизнеса: уточни историю (перерегистрация?)"
            )
    # Продуктовые и подрядные компании ломаются по-разному: продуктовая
    # теряет маржу при потере рынка, подрядная — при паузе в заказах.
    if ctx.business_model == "outsourced":
        lines.append("риск подрядчика: устойчивость зависит от потока заказов, "
                     "смотри концентрацию в закупках и госконтрактах")
    elif ctx.business_model == "retail":
        lines.append("риск розницы: смотри ликвидность и товарные запасы, "
                     "а не только выручку")
    return lines


def _plaintiff_lines(risk: RiskCollection | None) -> list[str]:
    """Компания сама взыскивает оплату — косвенный сигнал её платежного климата.

    Истец — не риск в классическом смысле, но поток АКТИВНЫХ исков о
    взыскании значит, что её заказчики систематически не платят: деньги
    до компании доходит с боем. Для неё самой это кассовый разрыв, для
    её контрагента — сигнал давать отсрочки осторожно: чужие задержки
    возвращаются задержками ниже по цепочке.
    """
    if risk is None:
        return []
    lines: list[str] = []
    for res in risk.results:
        a = res.arbitration
        if not a or not a.as_plaintiff_active.count:
            continue
        amount = a.as_plaintiff_active.total_amount
        lines.append(
            f"активных исков о взыскании: {a.as_plaintiff_active.count} "
            f"на {_fmt_amount(amount)} — компания сама ждёт оплаты от "
            "заказчиков; давать ей отсрочки платежа осторожно"
        )
    return lines


def _summary_lines(risk: RiskCollection | None, score: ScoreResult, debug: bool = False) -> list[str]:
    """Сжатая выжимка рисков для краткого отчёта."""
    lines: list[str] = []
    if risk is None:
        lines.append("реестровые проверки не проводились")
        return lines
    if debug and risk.coverage_note:
        lines.append(f"охват: {risk.coverage_note}")
    flags = [
        f.statement for res in risk.results for f in res.facts
        if f.kind == "registry_flag" and f.payload.get("flag")
    ]
    if flags:
        lines.extend(flags)
    for res in risk.results:
        if res.arbitration and res.arbitration.as_defendant.count:
            lines.append(
                f"ответчик по {res.arbitration.as_defendant.count} арбитражным делам "
                f"на {_fmt_amount(res.arbitration.as_defendant.total_amount)}"
            )
        if res.enforcement and res.enforcement.total:
            lines.append(
                f"исполнительных производств: {res.enforcement.total} "
                f"на {_fmt_amount(res.enforcement.outstanding or res.enforcement.total_amount)}"
            )
        if res.inspections and res.inspections.with_violations:
            lines.append(f"проверок с нарушениями: {res.inspections.with_violations}")
        if res.inspections and res.inspections.planned_inspections:
            lines.append(f"предстоящих/плановых проверок ЕРКНМ: {len(res.inspections.planned_inspections)}")
    return lines


_KIND_LABELS = {
    "leasing": "лизинг",
    "pledge": "залог имущества",
    "factoring": "факторинг",
    "guarantee": "независимая гарантия",
    "sro_membership": "членство в СРО",
    "fsa_certificate": "сертификат/декларация соответствия",
    "trademark": "товарный знак",
    "software_registry": "реестр отечественного ПО",
}


def _commercial_lines(risk: RiskCollection | None) -> list[str]:
    """Коммерческие сигналы из Федресурса, Росаккредитации и Роспатента.

    Это не риски: лизинг показывает активы, залог — кредит под развитие,
    факторинг — работу с отсрочками, сертификаты — чем реально торгуют,
    товарные знаки — нематериальные активы и реальный оборот.
    В краткий отчёт не входит: ради этого просят «подробно».
    """
    if risk is None:
        return []
    lines: list[str] = []
    counts: dict[str, int] = {}
    for f in risk.facts:
        if f.kind in _KIND_LABELS:
            counts[f.kind] = counts.get(f.kind, 0) + 1
    for kind, label in _KIND_LABELS.items():
        if counts.get(kind):
            if kind == "trademark":
                lines.append(f"{label}: {counts[kind]} в реестре Роспатента (ФИПС)")
            elif kind == "fsa_certificate":
                lines.append(f"{label}: {counts[kind]} в реестре Росаккредитации")
            elif kind == "software_registry":
                lines.append(f"{label}: {counts[kind]} в реестре Минцифры")
            else:
                lines.append(f"{label}: {counts[kind]} публ. в Федресурсе")

    foreign_mfgs = []
    for f in risk.facts:
        if f.kind == "fsa_certificate" and f.payload.get("is_foreign"):
            mfg = f.payload.get("manufacturer")
            origin = f.payload.get("origin_country") or "Импорт"
            if mfg:
                foreign_mfgs.append(f"{mfg} ({origin})")
    if foreign_mfgs:
        unique_mfgs = list(dict.fromkeys(foreign_mfgs))
        lines.append("зарубежные заводы и цепочки поставок (Росаккредитация): " + "; ".join(unique_mfgs[:5]))

    return lines


# Светофор рисков и ключевая суть оценки
_TRAFFIC_LIGHT_MAP = {
    "отлично": {
        "эмодзи": "🟢",
        "уровень_риска": "Низкий риск",
        "светофор": "🟢 Низкий риск",
        "суть_оценки": "Организация финансово устойчива, стоп-факторы и негативные отметки отсутствуют.",
    },
    "хорошо": {
        "эмодзи": "🟢",
        "уровень_риска": "Низкий риск",
        "светофор": "🟢 Низкий риск",
        "суть_оценки": "Стандартная деловая практика, существенных юридических или финансовых рисков не выявлено.",
    },
    "удовлетворительно": {
        "эмодзи": "🟡",
        "уровень_риска": "Умеренный риск",
        "светофор": "🟡 Умеренный риск",
        "суть_оценки": "Присутствуют факторы внимания: судебная нагрузка, снижение финансовых показателей или регуляторные вопросы.",
    },
    "рискованно": {
        "эмодзи": "🟠",
        "уровень_риска": "Высокий риск",
        "светофор": "🟠 Высокий риск",
        "суть_оценки": "Повышенная финансовая или судебная нагрузка, дисбаланс обязательств, риски задержки платежей.",
    },
    "не рекомендуется": {
        "эмодзи": "⛔",
        "уровень_риска": "Критический риск",
        "светофор": "⛔ Критический риск",
        "суть_оценки": "Критические реестровые отметки (банкротство, ликвидация, реорганизация или санкционные списки).",
    },
}


def _get_traffic_light(verdict_label: str) -> dict[str, str]:
    lbl = (verdict_label or "").strip().lower()
    return _TRAFFIC_LIGHT_MAP.get(
        lbl,
        {
            "эмодзи": "🟡",
            "уровень_риска": "Неопределённый риск",
            "светофор": "🟡 Неопределённый риск",
            "суть_оценки": "Требуется дополнительная ручная проверка сведений.",
        },
    )


def build_report(
    detail: str,
    context_result,   # ContextResult: обёртка со статусом и причиной
    risk: RiskCollection | None,
    score: ScoreResult,
    debug: bool = False,
    human_mode: bool | None = None,
) -> dict:
    """Собрать отчёт нужного объёма из уже собранных сведений.

    Никаких обращений к источникам — компоновка. Поля reason и coverage_note
    идут в отчёт всегда: сокращать можно объём данных, но не честность
    о том, чего проверка не охватила.
    """
    is_debug = debug or getattr(settings, "osint_debug", False)
    is_human = human_mode if human_mode is not None else getattr(settings, "human_friendly_mode", True)
    ctx = context_result.context if context_result else None
    traffic = _get_traffic_light(score.verdict.label)

    if detail == "brief":
        report: dict = {
            "inn": score.inn or (ctx.inn if ctx else ""),
            "карточка": {},
            "светофор": traffic["светофор"],
            "уровень_риска": traffic["уровень_риска"],
            "суть_оценки": traffic["суть_оценки"],
            "вердикт": score.verdict.label,
            "score": score.verdict.total_score,
            "warnings": score.warnings,
        }
        if ctx is not None:
            is_ip = len(str(ctx.inn or "")) == 12 or getattr(ctx, "entity_type", "") == "individual_entrepreneur"
            card_data = {
                "наименование": ctx.name_legal,
                "ИНН": ctx.inn,
                "ОГРН": ctx.ogrn,
                "тип_субъекта": "Индивидуальный предприниматель (ИП)" if is_ip else "Юридическое лицо",
                **{k: v for k, v in {
                    "город": ctx.city,
                    "статус": (ctx.status + " (зарегистрирован в ЕГРИП)") if (is_ip and ctx.status == "Действует") else ctx.status,
                    "деятельность": ctx.okved_text or ctx.okved_code,
                    "выручка_последний_год": ctx.revenue_latest,
                    "численность": ctx.employees,
                    "руководитель": ctx.director_fio or (ctx.name_legal if is_ip else None),
                }.items() if v is not None},
            }
            if is_ip and ctx.ogrn:
                card_data["ОГРНИП"] = ctx.ogrn
            report["карточка"] = card_data
        report["риски_кратко"] = _summary_lines(risk, score, debug=is_debug)
        if ctx is not None:
            fin_matrix = _build_financial_health_matrix(ctx)
            if fin_matrix:
                report["финансовая_матрица"] = fin_matrix
            stat_hr = _build_statutory_hr(ctx)
            if stat_hr:
                report["кадровый_потенциал_документы"] = stat_hr
            sales_intel = _build_sales_intelligence(ctx, risk=risk)
            if sales_intel:
                report["коммерческий_срез"] = {
                    "формула_бизнеса": sales_intel.get("формула_бизнеса"),
                    "целевой_сегмент": sales_intel.get("целевой_сегмент"),
                    "крючок_для_контакта": sales_intel.get("крючок_для_контакта"),
                }
        if score.reasons:
            report["основания"] = score.reasons
        if is_debug:
            diagnostic: dict = {}
            if context_result and context_result.reason:
                diagnostic["что_не_собралось"] = context_result.reason
                report["что_не_собралось"] = context_result.reason
            if risk and risk.coverage_note:
                diagnostic["охват"] = risk.coverage_note
            if risk is not None:
                failed = [r for r in risk.results if r.status != "ok"]
                if failed:
                    diagnostic["отказы_источников"] = [
                        {"source": r.source, "status": r.status, **({"reason": r.reason} if r.reason else {})}
                        for r in failed
                    ]
                diagnostic["источники"] = [
                    {"source": r.source, "status": r.status, **({"reason": r.reason} if r.reason else {})}
                    for r in risk.results
                ]
            if score.unmatched_fact_kinds:
                diagnostic["факты_без_критерия"] = score.unmatched_fact_kinds
            report["_диагностика_разработчика"] = diagnostic
        if is_human:
            from osint_mcp.tools.human_summary import build_human_summary, build_human_court_cases
            report["резюме_для_человека"] = build_human_summary(ctx, risk, score)
            court_cases = build_human_court_cases(risk)
            if court_cases:
                report["судебные_дела_сюжеты"] = court_cases
        report["scored_at"] = score.scored_at.isoformat()
        return report

    # full: краткое ядро плюс всё остальное
    report = build_report("brief", context_result, risk, score, debug=is_debug, human_mode=is_human)
    report.pop("scored_at", None)

    report["карточка"]["адрес"] = ctx.address_full if ctx else None
    if ctx is not None:
        report["карточка"]["учредители"] = ctx.founders
        if ctx.brand_resolved:
            report["карточка"]["рыночное_наименование"] = ctx.brand
            report["карточка"]["сайт"] = ctx.brand_domain or (
                ctx.extras.contacts.website if ctx.extras and ctx.extras.contacts else None
            )
            if ctx.social_links:
                report["карточка"]["соцсети"] = ctx.social_links
            if ctx.brand_summary:
                report["карточка"]["описание"] = ctx.brand_summary
        if ctx.size_category != "unknown":
            report["карточка"]["масштаб"] = ctx.size_category

    report["разбор"] = _full_sections(ctx, risk)
    if ctx is not None:
        fin_matrix = _build_financial_health_matrix(ctx)
        if fin_matrix:
            report["финансовая_матрица"] = fin_matrix
        if ctx.extras and ctx.extras.licenses:
            lic_breakdown = _build_license_breakdown(ctx.extras.licenses)
            if lic_breakdown:
                report["лицензии_расшифровка"] = lic_breakdown
        digital_fp = _build_digital_footprint(ctx)
        if digital_fp:
            report["цифровой_контур"] = digital_fp
        stat_hr = _build_statutory_hr(ctx)
        if stat_hr:
            report["кадровый_потенциал_документы"] = stat_hr
        aff_lite = _build_affiliations_lite(ctx)
        if aff_lite:
            report["корпоративные_связи_lite"] = aff_lite
    sales_intel = _build_sales_intelligence(ctx, risk=risk)
    if sales_intel:
        report["коммерческий_срез"] = sales_intel
    if is_debug and risk is not None:
        report["источники"] = [
            {"source": r.source, "status": r.status,
             **({"reason": r.reason} if r.reason else {})}
            for r in risk.results
        ]
    report["pending"] = [p.model_dump(mode="json") for p in score.pending]
    if is_debug and score.unmatched_fact_kinds:
        report["факты_без_критерия"] = score.unmatched_fact_kinds
    report["scored_at"] = score.scored_at.isoformat()
    return report


def build_batch_entry(
    context_result,
    risk: RiskCollection | None,
    score: ScoreResult,
    debug: bool = False,
) -> dict:
    """Одна строка пакетного отчёта: вердикт, суть, главные оговорки."""
    ctx = context_result.context if context_result else None
    traffic = _get_traffic_light(score.verdict.label)
    entry: dict = {
        "inn": score.inn or (ctx.inn if ctx else ""),
        "светофор": traffic["светофор"],
        "уровень_риска": traffic["уровень_риска"],
        "суть_оценки": traffic["суть_оценки"],
        "вердикт": score.verdict.label,
        "score": score.verdict.total_score,
    }
    if ctx is not None:
        entry["наименование"] = ctx.name_legal
        entry["статус"] = ctx.status
        entry["город"] = ctx.city
        stat_hr = _build_statutory_hr(ctx)
        if stat_hr:
            entry["кадры"] = {
                "штат_фнс": stat_hr.get("официальный_штат_фнс"),
                "вакансий": stat_hr.get("открыто_вакансий_30дней"),
                "динамика": stat_hr.get("динамика_найма"),
            }
    if score.warnings:
        entry["warnings"] = score.warnings[:3]
    is_debug = debug or getattr(settings, "osint_debug", False)
    if is_debug:
        if context_result and context_result.reason:
            entry["что_не_собралось"] = context_result.reason
        elif risk is not None and risk.coverage_note:
            entry["охват"] = risk.coverage_note
    summary = _summary_lines(risk, score, debug=is_debug)
    if summary:
        entry["риски_кратко"] = summary[:5]
    if score.reasons:
        entry["основания"] = score.reasons[:3]
    return entry
