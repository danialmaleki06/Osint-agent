"""Модуль коммерческого анализа контрагента для B2B-продаж и аккаунтинга.

Превращает сырые реестровые данные, стек, вакансии и судебную историю
в прикладную шпаргалку для сейла:
1. Что компания производит и кому продает (продуктовый профиль).
2. Текущие боли, узкие места и триггеры потребностей (Pains & Buying Signals).
3. Что конкретно им можно предложить (Offer Hypotheses).
4. Персонализированный крючок для первого контакта (Icebreaker).
"""

from __future__ import annotations

import re
from typing import Any

from osint_mcp.models import CompanyContext, RiskCollection


def _detect_business_formula(ctx: CompanyContext) -> tuple[str, str]:
    """Определяет формулу бизнеса и сегмент целевой аудитории."""
    okved = (ctx.okved_code or "")[:4]
    okved_name = (ctx.okved_text or "").lower()
    self_desc = (ctx.site_self_description or "").strip()
    has_software = bool(ctx.software_products)

    rev = ctx.revenue_latest or 0
    if rev >= 2_000_000_000 or ctx.size_category == "large":
        segment = "Крупный бизнес (Enterprise B2B)"
    elif rev >= 400_000_000 or ctx.size_category == "medium":
        segment = "Средний бизнес (Mid-market B2B)"
    elif rev > 0 or ctx.size_category in ("small", "micro"):
        segment = "Малый бизнес (SMB)"
    else:
        segment = "B2B-сегмент"

    # IT и программное обеспечение
    if has_software or okved.startswith(("62.", "63.")) or "программн" in okved_name:
        if "интегратор" in self_desc.lower() or "внедрен" in self_desc.lower():
            formula = "IT-вендор и системный интегратор корпоративного ПО"
        elif has_software:
            formula = "Разработчик тиражного программного обеспечения (ISV / SaaS-вендор)"
        else:
            formula = "IT-компания: заказная разработка и цифровые сервисы"
        return formula, segment

    # Строительство и проектирование
    if okved.startswith(("41.", "42.", "43.")) or "строительств" in okved_name:
        if rev >= 1_000_000_000:
            formula = "Генеральный подрядчик в сфере промышленного и гражданского строительства"
        else:
            formula = "Строительно-монтажный подрядчик и проектировщик"
        return formula, segment

    # Производство
    if (
        okved.startswith(tuple(f"{i:02d}." for i in range(10, 34)))
        or "производств" in okved_name
        or "завод" in (ctx.name_short or "").lower()
    ):
        formula = f"Производственное предприятие ({ctx.okved_text or 'промышленное производство'})"
        return formula, segment

    # Оптовая торговля и дистрибуция
    if okved.startswith("46.") or "оптов" in okved_name or "торговл" in okved_name:
        formula = f"Торгово-дистрибьюторская компания ({ctx.okved_text or 'оптовые поставки'})"
        return formula, segment

    # Транспорт и логистика
    if okved.startswith(("49.", "50.", "51.", "52.")) or "перевоз" in okved_name:
        formula = "Логистический оператор и транспортная компания"
        return formula, segment

    # Консалтинг, аудит, научная деятельность
    if okved.startswith(("69.", "70.", "71.", "72.", "73.")):
        formula = f"B2B-сервисная компания ({ctx.okved_text or 'профессиональные услуги'})"
        return formula, segment

    fallback = ctx.okved_text or "Коммерческая организация"
    return fallback, segment


def _extract_product_line(ctx: CompanyContext) -> list[dict[str, str]]:
    """Формирует список ключевых продуктов и брендовых активов."""
    products: list[dict[str, str]] = []

    # 1. Продукты из реестра отечественного ПО Минцифры
    for p in ctx.software_products:
        prod_info = {
            "название": p.name,
            "источник": "Реестр российского ПО Минцифры",
            "статус": f"Рег. №{p.reg_number or 'б/н'}",
        }
        if p.software_class:
            prod_info["класс_продукта"] = p.software_class
        if p.url:
            prod_info["ссылка"] = p.url
        products.append(prod_info)

    # 2. Товарные знаки компании
    if ctx.extras and ctx.extras.trademarks:
        existing_names = {p["название"].lower() for p in products}
        for tm in ctx.extras.trademarks[:4]:
            if tm.lower() not in existing_names:
                products.append({
                    "название": tm,
                    "источник": "Зарегистрированный товарный знак",
                    "статус": "Официальная торговая марка",
                })

    # 3. Флагманский бренд/сервис (если не упомянут выше)
    if ctx.brand and not any(p["название"].lower() == ctx.brand.lower() for p in products):
        products.insert(0, {
            "название": ctx.brand,
            "источник": "Корпоративный бренд",
            "статус": "Основная продуктовая витрина",
        })

    return products


def _extract_pains_and_triggers(
    ctx: CompanyContext,
    risk: RiskCollection | None = None,
    fiascos: list[Any] | None = None,
) -> list[dict[str, str]]:
    """Выявляет реальные точки боли, дефициты и триггеры для продажи."""
    pains: list[dict[str, str]] = []

    # 1. Кадровые боли: масштабный найм и дефицит ресурсов
    hiring = ctx.hiring
    if hiring and hiring.open_vacancies:
        if hiring.open_vacancies >= 40:
            pains.append({
                "категория": "масштабирование и дефицит рук",
                "сигнал": f"Открыто {hiring.open_vacancies} вакансий (масштабная экспансия)",
                "боль_контрагента": (
                    "Острый дефицит квалифицированных специалистов. Внутренний HR "
                    "не справляется с пиковым потоком, риск срыва сроков проектов."
                ),
            })
        elif hiring.open_vacancies >= 10:
            pains.append({
                "категория": "кадровое расширение",
                "сигнал": f"Открыто {hiring.open_vacancies} вакансий",
                "боль_контрагента": "Расширение команд под новые контракты, потребность в онбординге и закрытии позиций.",
            })

        # Найм топ-менеджмента и ключевых тимлидов
        if hiring.leadership_roles:
            roles_str = "; ".join(hiring.leadership_roles[:3])
            pains.append({
                "категория": "смена ЛПР (окно возможностей)",
                "сигнал": f"Ищут руководителей: {roles_str}",
                "боль_контрагента": (
                    "Перестройка процессов или создание новых направлений. Новые руководители "
                    "в первые 90 дней пересматривают старых подрядчиков и формируют собственный пул."
                ),
            })

    # 2. Технологический стек и инфраструктурный контраст
    site_tech = ctx.site_tech
    rev = ctx.revenue_latest or 0
    if site_tech:
        cms_crm = []
        if site_tech.cms:
            cms_crm.extend(site_tech.cms)
        if site_tech.crm_widgets:
            cms_crm.extend(site_tech.crm_widgets)

        # Контраст: многомиллиардный бизнес на легких конструкторах/виджетах
        has_smb_tech = any(
            t.lower() in ("tilda", "jivo", "amocrm", "bitrix", "wix", "wordpress")
            for t in cms_crm
        )
        if rev >= 500_000_000 and has_smb_tech:
            tech_str = ", ".join(cms_crm)
            pains.append({
                "категория": "инфраструктурный контраст",
                "сигнал": f"Стек сайта ({tech_str}) при выручке {rev / 1e9:.1f} млрд ₽",
                "боль_контрагента": (
                    "Бизнес перерос базовые веб-решения: требуются отказоустойчивые корпоративные порталы, "
                    "интеграции с ERP, безопасность и глубокая аналитика клиентских путей."
                ),
            })

    # 3. Судебные претензии и разногласия по качеству/оплатам
    if risk:
        for f in risk.facts:
            if f.kind == "arbitration":
                is_defendant = "ответчик" in f.statement.lower()
                claims = 0.0
                if f.payload:
                    claims = float(f.payload.get("sum_rub") or f.payload.get("claims_rub") or 0.0)
                    if f.payload.get("defendant"):
                        is_defendant = True
                elif "млн" in f.statement:
                    m_claims = re.search(r"(\d+(?:\.\d+)?)\s*млн", f.statement)
                    if m_claims:
                        claims = float(m_claims.group(1)) * 1_000_000

                if is_defendant or claims > 0:
                    pains.append({
                        "категория": "договорные споры и качество сдачи",
                        "сигнал": f.statement[:120],
                        "боль_контрагента": (
                            "Конфликты по закрывающим актам, качеству работ или задержкам оплат. "
                            "Потребность в строгой юридической фиксации ТЗ и критериев приемки."
                        ),
                    })
                    break

    # 4. Репутационные происшествия и сбои (СМИ, VC, Habr)
    if fiascos:
        for fc in fiascos:
            st = getattr(fc, "statement", "") or ""
            kind = getattr(fc, "kind", "") or ""
            if "vendor_dispute" in kind or "претензия" in st.lower() or "не платят" in st.lower():
                pains.append({
                    "категория": "конфликты с подрядчиками",
                    "сигнал": "Публичные жалобы контрагентов в СМИ / профильных медиа",
                    "боль_контрагента": "Сложности в согласовании условий оплат и приемки этапов.",
                })
                break
            if "tech_incident" in kind or "сбой" in st.lower() or "авария" in st.lower():
                pains.append({
                    "категория": "стабильность IT-контура",
                    "сигнал": "Следы технических инцидентов / аварий в открытых источниках",
                    "боль_контрагента": "Угроза простоев, потребность в аудите надежности и отказоустойчивости.",
                })
                break

    return pains


def _build_offer_hypotheses(
    ctx: CompanyContext,
    pains: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Формирует 3–4 прикладных оффера для менеджера."""
    offers: list[dict[str, str]] = []
    has_it = bool(ctx.software_products) or (ctx.okved_code or "").startswith(("62.", "63."))
    hiring = ctx.hiring

    # 1. Аутстаффинг и проектные команды
    if (hiring and hiring.open_vacancies >= 10) or has_it:
        tech_roles = (
            ", ".join(hiring.roles[:3])
            if hiring and hiring.roles
            else "разработчиков и аналитиков"
        )
        offers.append({
            "направление": "IT-аутстаффинг и усиление команд",
            "кому_предлагать": "CTO / Директору по разработке / Руководителю проектного офиса",
            "ценность_оффера": (
                f"Быстрое закрытие дефицита инженеров ({tech_roles}) под пиковые релизы "
                "и контракты без долгих поисков и перегруза штата."
            ),
        })

    # 2. Инфраструктура, Cloud и кибербезопасность
    rev = ctx.revenue_latest or 0
    if rev >= 500_000_000 or has_it:
        offers.append({
            "направление": "Инфраструктурные и облачные решения (IaaS/DevOps/ИБ)",
            "кому_предлагать": "IT-директору (CIO) / Директору по информационной безопасности (CISO)",
            "ценность_оффера": (
                "Аудит отказоустойчивости, защита от DDoS, резервирование мощностей "
                "и соответствие требованиям регуляторов (152-ФЗ, КИИ)."
            ),
        })

    # 3. Enterprise-разработка и модернизация веб-контура
    site_tech = ctx.site_tech
    if site_tech and site_tech.cms and "tilda" in [c.lower() for c in site_tech.cms] and rev >= 300_000_000:
        offers.append({
            "направление": "Кастомная веб-разработка и личные кабинеты",
            "кому_предлагать": "Директору по маркетингу (CMO) / Коммерческому директору",
            "ценность_оффера": (
                "Переход с конструкторов сайтов на масштабируемый портал с личными кабинетами B2B-клиентов "
                "и бесшовной интеграцией в CRM/ERP."
            ),
        })

    # 4. Юридический консалтинг и управление дебиторкой
    has_disputes = any(p["категория"] == "договорные споры и качество сдачи" for p in pains)
    if has_disputes:
        offers.append({
            "направление": "Юридический аудит контрактов и ЭДО",
            "кому_предлагать": "Финансовому директору (CFO) / Руководителю юридического департамента",
            "ценность_оффера": (
                "Разработка детальных регламентов сдачи-приемки работ и факторинг "
                "для устранения кассовых разрывов при задержке оплат заказчиками."
            ),
        })

    # 5. Рекрутмент и HR-Tech (если найм огромный)
    if hiring and hiring.open_vacancies >= 30:
        offers.append({
            "направление": "Точечный рекрутмент и HR-автоматизация",
            "кому_предлагать": "HR-директору (HRD)",
            "ценность_оффера": "Закрытие редких технических и руководящих позиций с гарантией замены.",
        })

    return offers[:4]


def _generate_outreach_hook(
    ctx: CompanyContext,
    pains: list[dict[str, str]],
    offers: list[dict[str, str]],
) -> str:
    """Генерирует готовый персонализированный заход (icebreaker) для холодного контакта."""
    brand = ctx.brand or ctx.name_short or "вашу компанию"
    hiring = ctx.hiring

    # Триггер 1: Найм конкретного руководителя
    if hiring and hiring.leadership_roles:
        target_role = hiring.leadership_roles[0]
        return (
            f"«Добрый день! Обратил внимание, что {brand} сейчас активно усиливает "
            f"руководящую команду по направлению «{target_role}» под масштабирование проектов. "
            f"Мы помогаем быстро разгрузить команду и предоставить проверенные ресурсы "
            f"для запуска новых этапов. Подскажите, актуален ли сейчас диалог по этому направлению?»"
        )

    # Триггер 2: Продукты в реестре отечественного ПО
    if ctx.software_products:
        prod_name = ctx.software_products[0].name
        return (
            f"«Добрый день! Следим за развитием ваших решений, в частности платформы «{prod_name}». "
            f"Видим, что продукт включён в реестр отечественного ПО и активно внедряется. "
            f"Мы сотрудничаем с Enterprise-вендорами и помогаем ускорять внедрения и интеграции. "
            f"Будет ли интересно обсудить возможное технологическое партнёрство?»"
        )

    # Триггер 3: Масштабное расширение команд
    if hiring and hiring.open_vacancies >= 20:
        top_roles = ", ".join(hiring.roles[:2]) if hiring.roles else "специалистов"
        return (
            f"«Добрый день! Заметили активную экспансию {brand} — более {hiring.open_vacancies} "
            f"открытых позиций, в том числе по направлению {top_roles}. "
            f"Помогаем технологическим компаниям закрывать дефицит квалифицированных специалистов "
            f"без затягивания сроков проектных внедрений. Найдётся ли 10 минут на короткое знакомство?»"
        )

    # Триггер 4: Позиционирование с сайта
    if ctx.site_self_description:
        return (
            f"«Добрый день! Обратил внимание на ваше позиционирование в части «{ctx.site_self_description}». "
            f"Мы работаем с компаниями вашего масштаба и предлагаем решения, которые помогают "
            f"оптимизировать операционные процессы и снизить издержки. Подскажите, с кем в вашей команде "
            f"можно обсудить это направление?»"
        )

    return (
        f"«Добрый день! Изучили профиль {brand} в сфере {ctx.okved_text or 'вашей отрасли'}. "
        f"Видим устойчивые показатели роста и масштабирование бизнеса. "
        f"Хотели бы предложить решения для усиления вашей инфраструктуры и процессов. "
        f"С кем из коллег было бы продуктивно обсудить детали?»"
    )


def build_sales_intelligence(
    ctx: CompanyContext | None,
    risk: RiskCollection | None = None,
    fiascos: list[Any] | None = None,
    detail: str = "full",
) -> dict[str, Any]:
    """Главная точка входа: собирает детерминированный коммерческий срез для B2B-сейла."""
    if ctx is None:
        return {}

    formula, segment = _detect_business_formula(ctx)
    products = _extract_product_line(ctx)
    pains = _extract_pains_and_triggers(ctx, risk=risk, fiascos=fiascos)
    offers = _build_offer_hypotheses(ctx, pains)
    hook = _generate_outreach_hook(ctx, pains, offers)

    intelligence: dict[str, Any] = {
        "формула_бизнеса": formula,
        "целевой_сегмент": segment,
        "продуктовая_линейка": products,
        "боли_и_триггеры": pains,
        "что_предложить": offers,
        "крючок_для_контакта": hook,
    }

    if ctx.site_self_description:
        intelligence["самопозиционирование_с_сайта"] = ctx.site_self_description

    return intelligence
