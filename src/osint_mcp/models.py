"""Модели данных.

Pydantic здесь работает в трёх ролях одновременно:
  1. проверяет данные на границе системы;
  2. из аннотаций типов генерируется схема, которую видит модель;
  3. задаёт контракт, на который опираются тесты.

Один источник правды — рассинхронизироваться нечему.
"""

import re
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# «Не найдено» и «выбирайте из нескольких» — разные состояния, и путать
# их нельзя: по второму агент обязан показать перечень кандидатов,
# а по первому перечень пуст, и показывать нечего.
Confidence = Literal["high", "medium", "low", "none"]
SourceStatus = Literal["ok", "unavailable", "partial", "skipped"]


# ──────────────────────────  Служебное  ──────────────────────────

class ServerHealth(BaseModel):
    """Состояние сервера. Служит для отделения проблем связи от проблем логики."""

    status: Literal["ok"] = "ok"
    server: str = Field(description="Имя сервера")
    version: str = Field(description="Версия сервера")
    checked_at: datetime = Field(description="Время ответа сервера, UTC")
    tools: list[str] = Field(description="Зарегистрированные инструменты")


class InnCheck(BaseModel):
    """Результат проверки ИНН по контрольной сумме.

    valid=False — это нормальный результат, а не ошибка выполнения.
    """

    inn: str = Field(description="Проверявшийся номер в исходном виде")
    valid: bool = Field(description="Прошёл ли номер проверку контрольной суммы")
    kind: Literal["legal_entity", "individual", "unknown"] = Field(
        description=(
            "legal_entity — 10 знаков, организация; "
            "individual — 12 знаков, ИП или физлицо; "
            "unknown — длина не соответствует ни одному формату"
        )
    )
    reason: str | None = Field(
        default=None,
        description="Причина отбраковки. Заполняется только при valid=False",
    )


# ──────────────────────────  Установление личности  ──────────────────────────

class Candidate(BaseModel):
    """Одна организация-кандидат при разрешении неоднозначного запроса.

    Набор полей подобран так, чтобы человек мог отличить кандидатов
    друг от друга: город, статус и дата регистрации обычно достаточны.
    """

    inn: str = Field(description="ИНН")
    ogrn: str | None = Field(default=None, description="ОГРН")
    name: str = Field(description="Наименование по реестру")
    short_name: str | None = Field(default=None, description="Краткое наименование")
    city: str | None = Field(default=None, description="Город регистрации")
    status: str | None = Field(
        default=None, description="Статус: действующая, ликвидирована, в стадии ликвидации"
    )
    registered_at: date | None = Field(default=None, description="Дата регистрации")
    director: str | None = Field(default=None, description="ФИО руководителя")
    okved: str | None = Field(default=None, description="Основной код ОКВЭД")


class ResolveResult(BaseModel):
    """Результат установления личности компании.

    ВАЖНО: при confidence="low" выбор кандидата остаётся за пользователем.
    Инструмент намеренно не выбирает сам.
    """

    query: str = Field(description="Исходный запрос")
    status: SourceStatus = Field(default="ok", description="Состояние источника")
    reason: str | None = Field(
        default=None, description="Причина, если status не 'ok'"
    )
    confidence: Confidence = Field(
        description=(
            "high — организация определена однозначно; "
            "medium — вероятное совпадение, стоит упомянуть выбор; "
            "low — несколько равнозначных кандидатов, нужен выбор пользователя; "
            "none — выбирать не из чего: не найдено, номер некорректен либо "
            "источник не ответил. Перечень кандидатов при этом пуст"
        )
    )
    total_found: int = Field(default=0, description="Сколько всего найдено")
    candidates: list[Candidate] = Field(
        default_factory=list, description="Кандидаты, наиболее вероятные первыми"
    )
    hint: str | None = Field(
        default=None, description="Пояснение для агента: что делать дальше"
    )


class SourceLink(BaseModel):
    """Проверяемая ссылка на первоисточник по одному направлению.

    Собирается всегда при сборе контекста, но в отчёты не выводится:
    объём отчёта фиксирован, а ссылки отдаются отдельным дозапросом
    (get_company_links). Так отчёт остаётся коротким, но проверяемым:
    любая цифра может быть вскрыта до первоисточника по требованию.
    """

    what: str = Field(description="Что можно проверить по этой ссылке")
    url: str = Field(description="Ссылка на первоисточник")
    source: str = Field(description="Какой источник дал ссылку")


class FinancialYear(BaseModel):
    """Финансовые показатели за один год."""

    year: int = Field(description="Отчётный год")
    revenue: float | None = Field(default=None, description="Выручка, рублей")
    profit: float | None = Field(default=None, description="Чистая прибыль, рублей")
    assets: float | None = Field(default=None, description="Итог баланса, рублей")
    balance: float | None = Field(
        default=None,
        description="Валюта баланса (итог актива и пассива), рублей",
    )
    equity: float | None = Field(
        default=None,
        description=(
            "Собственный капитал, рублей. Отрицательный при положительном "
            "балансе — устойчивый признак предбанкротного состояния"
        ),
    )
    report_url: str | None = Field(
        default=None,
        description=(
            "Прямая ссылка на официальную отчётность ФНС (bo.nalog.gov.ru). "
            "Первичная проверяемая ссылка для любого финансового утверждения"
        ),
    )
    loans: float | None = Field(
        default=None,
        description=(
            "Долгосрочные заёмные средства (строка 1410), рублей. None — "
            "строка в отчётности не заполнена либо источник не отдал"
        ),
    )
    cash: float | None = Field(
        default=None,
        description=(
            "Денежные средства (строка 1250), рублей. Вместе с дебиторкой — "
            "ликвидные активы против краткосрочных долгов"
        ),
    )
    short_debt: float | None = Field(
        default=None,
        description=(
            "Краткосрочные обязательства (итог раздела V, строка 1500), рублей. "
            "Вместе с loans — вся долговая нагрузка"
        ),
    )
    receivables: float | None = Field(
        default=None,
        description=(
            "Дебиторская задолженность (строка 1230), рублей. Подавляющая "
            "доля к активам — деньги заморожены в чужих долгах"
        ),
    )
    payables: float | None = Field(
        default=None,
        description=(
            "Кредиторская задолженность (строка 1520), рублей. Рост выше "
            "дебиторки — кассовый разрыв: деньги чужие и не свои"
        ),
    )


class LicenseInfo(BaseModel):
    """Лицензия организации.

    Лицензия — контроль подтверждённой законности деятельности. Для
    регулируемых отраслей её отсутствие не «нет данных», а стоп-сигнал.
    """

    number: str = Field(description="Номер лицензии")
    issuer: str | None = Field(default=None, description="Лицензирующий орган")
    issued_at: date | None = Field(default=None, description="Дата выдачи")
    activity: str | None = Field(default=None, description="Лицензированный вид деятельности")


class ContactInfo(BaseModel):
    """Контакты из карточки ЕГРЮЛ.

    Сайт нужен не для связи, а для проверки: совпадение домена карточки
    с доменом рыночного наименования отделяет настоящую компанию от омонима.
    """

    phones: list[str] = Field(default_factory=list, description="Телефоны")
    emails: list[str] = Field(default_factory=list, description="Адреса электронной почты")
    website: str | None = Field(default=None, description="Сайт из карточки ЕГРЮЛ")


class TimelineEvent(BaseModel):
    """Существенное событие истории организации.

    Частые смены руководителя или учредителей — признак конфликта
    собственников, перетасовки под проблему или самой однодневки.
    Единичная смена — норма жизни; оценивается частота и свежесть.
    """

    event_date: date | None = Field(default=None, description="Дата события")
    event: str = Field(description="Формулировка из реестра, как записано")


class CardExtras(BaseModel):
    """Дополнительно к карточке: налоги, лицензии, контакты, массовость адреса.

    Всё это приходит из той же карточки Checko и раньше отбрасывалось.
    Пустое поле здесь означает «в карточке не заполнено»: различать
    «проверено, отсутствует» и «не смогли получить» обязан reason
    результата сборки, а не эта модель.
    """

    tax_debt: float | None = Field(
        default=None,
        description=(
            "Задолженность по налогам (недоимка), рублей. None — сведений "
            "в карточке нет, а НЕ отсутствие долга. Положительное значение — "
            "сильный негативный сигнал"
        ),
    )
    tax_paid_total: float | None = Field(
        default=None,
        description=(
            "Всего уплачено налогов и взносов за последний отчётный год, рублей. "
            "Резко не сходится с заявленным масштабом — признак серой деятельности"
        ),
    )
    tax_year: int | None = Field(default=None, description="Отчётный год налоговых сведений")
    tax_mode: list[str] = Field(
        default_factory=list,
        description="Особые налоговые режимы (УСН, ЕСХН и прочие); пусто — обычный порядок либо нет данных",
    )
    okved_extra: list[str] = Field(
        default_factory=list,
        description=(
            "Дополнительные ОКВЭДы строкой «код — название». Основной код — "
            "чем компания зарегистрирована, дополнительные — чем занимается "
            "фактически; новый код часто означает запуск нового направления"
        ),
    )
    trademarks: list[str] = Field(
        default_factory=list,
        description="Товарные знаки компании. Непустой список — рыночное имя подтверждено в обороте",
    )
    mass_address_orgs: list[str] = Field(
        default_factory=list,
        description=(
            "ОГРН организаций, зарегистрированных по тому же адресу. "
            "Список длиннее единицы — массовый адрес. Существенно для микро "
            "и малого бизнеса, к крупным неприменимо"
        ),
    )
    address_unreliable: bool = Field(
        default=False,
        description=(
            "Адрес признан ФНС недостоверным. Сам по себе стоп-сигнал: "
            "связь с организацией по такому адресу не гарантирована"
        ),
    )
    licenses: list[LicenseInfo] = Field(
        default_factory=list,
        description="Действующие лицензии организации",
    )
    contacts: ContactInfo | None = Field(
        default=None,
        description="Телефоны, электронная почта, сайт из карточки ЕГРЮЛ",
    )


class HiringInfo(BaseModel):
    """Найм компании по данным HeadHunter.

    Вакансии — самый быстрый сигнал направления компании: что ищет,
    какие технологии использует, куда растёт. Список профессий читается
    как список текущих потребностей — для продаж это готовый повод
    разговора, для анализа — стек и направление развития.
    """

    open_vacancies: int = Field(
        default=0, description="Сколько открытых вакансий найдено"
    )
    roles: list[str] = Field(
        default_factory=list,
        description="Названия вакансий. Перечень = текущие потребности компании",
    )
    found_by_name: bool = Field(
        default=False,
        description=(
            "True — вакансии найдены поиском по имени компании: возможны "
            "совпадения названий у разных компаний, вакансии могут быть "
            "не той организации"
        ),
    )
    reason: str | None = Field(
        default=None,
        description="Почему не удалось, если open_vacancies=0 и reason заполнен",
    )
    leadership_roles: list[str] = Field(
        default_factory=list,
        description="Руководящие позиции (триггеры продаж / окно входа для B2B)",
    )
    tech_stack: list[str] = Field(
        default_factory=list,
        description="Стек софта и технологий, упомянутый в вакансиях (1С, CRM, языки)",
    )
    it_investing: bool = Field(
        default=False,
        description="Признаки активного найма в IT/R&D (разработчики, инженеры, аналитики)",
    )
    employer_id: str | None = Field(
        default=None,
        description="ID работодателя на HeadHunter при точном сопоставлении",
    )
    employer_name: str | None = Field(
        default=None,
        description="Наименование верифицированного работодателя на HeadHunter",
    )


class MspInfo(BaseModel):
    """Сведения из единого реестра субъектов МСП (rmsp.nalog.ru).

    Реестр — независимое подтверждение масштаба: категория выставляется
    ФНС по выручке и численности, а не по нашей оценке. Исключение
    действующей компании из реестра — повод перепроверить масштаб.
    """

    in_registry: bool = Field(default=False, description="Значится ли в реестре МСП")
    category: str | None = Field(
        default=None, description="Категория: micro, small или medium; None — не указана"
    )
    employees: int | None = Field(
        default=None, description="Среднесписочная численность по данным реестра"
    )
    included_at: date | None = Field(default=None, description="Дата включения в реестр")
    excluded_at: date | None = Field(
        default=None, description="Дата исключения из реестра, если произошло"
    )
    is_active: bool = Field(
        default=True,
        description="Действующий субъект реестра. False — исключён: данные могли устареть",
    )


class SslInfo(BaseModel):
    """Сведения о SSL-сертификате официального сайта."""

    valid: bool = Field(default=False, description="Валиден ли SSL-сертификат")
    issuer: str | None = Field(default=None, description="Кем выдан сертификат (Let's Encrypt, DigiCert и т.д.)")
    expires_at: date | None = Field(default=None, description="Дата окончания действия сертификата")
    days_left: int | None = Field(default=None, description="Сколько дней осталось до истечения сертификата")
    error: str | None = Field(default=None, description="Ошибка при проверке сертификата")


class SiteTechInfo(BaseModel):
    """Технологический и маркетинговый стек, обнаруженный на сайте компании."""

    analytics: list[str] = Field(
        default_factory=list,
        description="Системы аналитики и пиксели (Яндекс.Метрика, Google Analytics, VK Pixel, Roistat)",
    )
    crm_widgets: list[str] = Field(
        default_factory=list,
        description="CRM-виджеты и онлайн-чаты (Bitrix24, JivoSite, Carrot quest, Calltouch)",
    )
    cms: list[str] = Field(
        default_factory=list,
        description="CMS и платформы (1C-Битрикс, WordPress, Tilda, OpenCart и т.д.)",
    )
    marketing_active: bool = Field(
        default=False,
        description="Признаки активного маркетинга (рекламные пиксели и сквозная аналитика)",
    )
    tracker_ids: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Идентификаторы систем веб-аналитики (Yandex Metrika: ym:XXXX, Google Analytics: G-XXXX/UA-XXXX, VK/Mail.ru: tmr:XXXX)",
    )


class SoftwareProduct(BaseModel):
    """Программный продукт из единого реестра российского ПО (Минцифры)."""

    name: str = Field(description="Наименование программного обеспечения")
    reg_number: str | None = Field(default=None, description="Реестровый номер записи")
    reg_date: str | None = Field(default=None, description="Дата включения в реестр")
    status: str = Field(default="В реестре", description="Статус в реестре")
    software_class: str | None = Field(default=None, description="Класс программного обеспечения")
    url: str | None = Field(default=None, description="Ссылка на запись в реестре Минцифры")


class CompanyContext(BaseModel):
    """Опорный контекст компании. Вход для всех последующих проверок.

    Разделение полей принципиально:
      authoritative — пришло из реестра, можно утверждать в досье;
      derived       — выведено нами, годится для поиска, но не для утверждений.
    """

    # authoritative — из реестра
    inn: str = Field(description="ИНН, либо УНП для Беларуси, либо БИН для Казахстана")
    country: Literal["RU", "BY", "KZ", "unknown"] = Field(
        default="RU",
        description=(
            "Страна регистрации. Проверки рисков (суды, банкротство, приставы, "
            "закупки) доступны ТОЛЬКО для RU. Для BY и KZ отсутствие находок "
            "означает, что проверка не проводилась"
        ),
    )
    ogrn: str | None = Field(default=None, description="ОГРН")
    name_legal: str = Field(description="Полное наименование по ЕГРЮЛ")
    name_short: str | None = Field(default=None, description="Краткое наименование")
    status: str | None = Field(default=None, description="Статус организации")
    registered_at: date | None = Field(
        default=None,
        description=(
            "Дата регистрации. Используется как фильтр: публикация, вышедшая "
            "раньше этой даты, не может относиться к данной организации"
        ),
    )
    address_full: str | None = Field(default=None, description="Юридический адрес")
    city: str | None = Field(default=None, description="Город — якорь для поиска")
    region: str | None = Field(default=None, description="Регион")
    director_fio: str | None = Field(
        default=None,
        description="ФИО руководителя. Используется и как якорь, и как отрицательный признак",
    )
    director_post: str | None = Field(default=None, description="Должность руководителя")
    founders: list[str] = Field(default_factory=list, description="Учредители")
    okved_code: str | None = Field(default=None, description="Основной код ОКВЭД")
    okved_text: str | None = Field(default=None, description="Расшифровка ОКВЭД")
    capital: float | None = Field(default=None, description="Уставный капитал, рублей")

    # derived — выведено нами
    name_variants: list[str] = Field(
        default_factory=list,
        description="Варианты написания названия для поиска, от точного к широкому",
    )
    industry_terms: list[str] = Field(
        default_factory=list,
        description="Отраслевые слова по коду ОКВЭД — якоря для веб-поиска",
    )
    brand_resolved: bool = Field(
        default=False,
        description=(
            "Установлено ли рыночное название. Пока False, веб-поиск ведётся "
            "только по юридическому наименованию, и отсутствие находок "
            "НЕ доказывает отсутствие негатива"
        ),
    )
    brand: str | None = Field(
        default=None, description="Рыночное наименование — как компанию называют в публикациях"
    )
    former_names: list[str] = Field(
        default_factory=list,
        description=(
            "Прежние наименования организации. Смена названия — известный "
            "способ отделиться от прежней репутации, поэтому публикации "
            "нужно искать и по ним тоже"
        ),
    )
    brand_domain: str | None = Field(default=None, description="Официальный сайт")
    brand_summary: str | None = Field(default=None, description="Описание деятельности")
    domain_created_at: date | None = Field(
        default=None,
        description=(
            "Дата создания домена сайта (WHOIS). Домен моложе заявленного "
            "возраста бизнеса — признак перерегистрации; None — домена нет "
            "или WHOIS не ответил (см. что_не_собралось)"
        ),
    )
    site_self_description: str | None = Field(
        default=None,
        description=(
            "Как компания называет себя сама: заголовок H1 или meta description "
            "главной страницы. Самопрезентация информативнее ОКВЭДов, но это "
            "маркетинговый текст — не факт"
        ),
    )
    ssl_info: SslInfo | None = Field(
        default=None,
        description="Сведения о SSL-сертификате официального сайта",
    )
    site_tech: SiteTechInfo | None = Field(
        default=None,
        description="Стек технологий и маркетинга, найденный на сайте компании",
    )
    software_products: list["SoftwareProduct"] = Field(
        default_factory=list,
        description="Программные продукты компании в едином реестре российского ПО (Минцифры)",
    )

    # масштаб — определяет применимость признаков риска
    size_category: Literal["micro", "small", "medium", "large", "unknown"] = Field(
        default="unknown",
        description=(
            "Масштаб организации. Существенно для оценки: признаки вроде "
            "массового адреса значимы для малого бизнеса и неприменимы к крупному"
        ),
    )
    employees: int | None = Field(default=None, description="Среднесписочная численность")
    branches: int | None = Field(
        default=None,
        description=(
            "Сколько филиалов у организации. None — источник не ответил или "
            "карточка не содержит сведений, число НЕ УСТАНОВЛЕНО, а не равно "
            "нулю. Явный ноль означает: сведения есть, филиалов нет"
        ),
    )
    representative_offices: int | None = Field(
        default=None,
        description=(
            "Сколько представительств. None — не установлено; явный ноль — "
            "сведения есть, представительств нет"
        ),
    )
    revenue_latest: float | None = Field(
        default=None, description="Выручка за последний отчётный год, рублей"
    )
    fin_history: list[FinancialYear] = Field(
        default_factory=list,
        description=(
            "Финансовая история до пяти лет, свежие первыми. Оценивать "
            "устойчивость по одному году нельзя: падение выручки, уход "
            "в убыток и проедание собственного капитала видны только в динамике"
        ),
    )
    social_links: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Официальные аккаунты (telegram, vk и прочие) — придаток рыночного "
            "наименования. Заполняется только при brand_resolved=True"
        ),
    )
    events: list[TimelineEvent] = Field(
        default_factory=list,
        description=(
            "Существенные события истории: смены наименования, руководителя, "
            "адреса, реорганизация. Даты и формулировки — как в реестре"
        ),
    )
    extras: CardExtras | None = Field(
        default=None,
        description=(
            "Налоги, лицензии, контакты, массовость адреса. None — карточка "
            "второго источника не отвечала; при source='checko' заполнено всегда, "
            "когда карточка получена"
        ),
    )
    msp: MspInfo | None = Field(
        default=None,
        description=(
            "Сведения из реестра МСП (бесплатный источник ФНС): независимое "
            "подтверждение категории масштаба. None — источник не отвечал "
            "либо организация в реестре не значится"
        ),
    )
    hiring: HiringInfo | None = Field(
        default=None,
        description=(
            "Найм по HeadHunter: открытые вакансии и названия. Список ролей "
            "читается как список текущих потребностей компании. None — "
            "источник не опрашивался либо не ответил (см. hiring.reason)"
        ),
    )
    source_links: list[SourceLink] = Field(
        default_factory=list,
        description=(
            "Проверяемые ссылки на первоисточники: карточки реестров, PDF "
            "отчётности ФНС, кадровые дела. В отчёты НЕ выводятся — отдаются "
            "дозапросом get_company_links, когда пользователь просит подтвердить"
        ),
    )
    business_model: str | None = Field(
        default=None,
        description=(
            "Модель бизнеса (эвристика, не факт): product — свой продукт "
            "(товарные знаки, ИТ-аккредитация); outsourced — работы по заказу "
            "клиентов; retail — розница/услуги населению. None — данных для "
            "вывода не хватило. Эвристику проверяй по фактам, не выдавай за истину"
        ),
    )
    business_stage: str | None = Field(
        default=None,
        description=(
            "Стадия бизнеса (эвристика): young — до 3 лет; growth — растущая "
            "выручка или найм; mature — старше 8 лет со стабильной численностью; "
            "shrinking — численность падает при живой выручке. None — мало данных"
        ),
    )

    # служебное
    source: str = Field(default="", description="Откуда получены данные")
    retrieved_at: datetime | None = Field(default=None, description="Время получения")


# ──────────────────────────  Факты и риски  ──────────────────────────

# Ядро видов фактов: реестровые источники проекта. Захардкожено
# намеренно — это контракт с парсерами Checko/DaData, и произвольные
# строки сюда попадать не должны.
CORE_FACT_KINDS = frozenset({
    "registry", "arbitration", "bankruptcy", "enforcement",
    "procurement", "registry_flag", "news",
    # Федресурс: коммерческие сведения (лизинг, залоги, факторинг,
    # гарантии, СРО) и неопознанные существенные факты
    "leasing", "pledge", "factoring", "guarantee", "sro_membership",
    "fedresurs_publication",
    # ФГИС Росаккредитация: сертификаты и декларации соответствия
    "fsa_certificate",
    # Роспатент / ФИПС: товарные знаки
    "trademark",
    # Единый реестр российского ПО (Минцифры)
    "software_registry",
    # ЕРКНМ: предстоящие и плановые проверки
    "planned_inspection",
})

FactKind = Literal[
    "registry", "arbitration", "bankruptcy", "enforcement",
    "procurement", "registry_flag", "news",
    "leasing", "pledge", "factoring", "guarantee", "sro_membership",
    "fedresurs_publication",
    "fsa_certificate",
    "trademark",
    "software_registry",
    "planned_inspection",
]

# Формат вида факта для пополняемых источников (адаптеры, плагины).
# Должен быть совместим с FactKind: новый вид расширяет ядро, а не
# конфликтует с ним. Примеры валидных: "banned_list", "rss_fns",
# "custom_site_vacancy". Невалидные: "Registry" (регистр), "a-b"
# (дефис), "" (пустое).
_EXT_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


def is_valid_ext_kind(kind: str) -> bool:
    """Проверка вида факта из пополняемого источника.

    Правила: латиница в нижнем регистре, цифры, подчёркивания;
    начинается с буквы; 3–64 символа. Ядро (FactKind) проходит
    всегда — расширения не должны ломать существующие источники.
    """
    if not kind:
        return False
    if kind in CORE_FACT_KINDS:
        return True
    return bool(_EXT_KIND_PATTERN.match(kind))


class ExtFact(BaseModel):
    """Факт из пополняемого источника (адаптер, плагин, пользовательский парсер).

    Отличие от Fact: kind — валидированная строка, а не Literal. Новый
    источник приносит свой вид факта без правки core-моделей. В скоринг
    попадает на общих основаниях: пока в scoring.yaml нет критерия с
    этим kind, факты лежат в unmatched_fact_kinds и оценку не меняют.
    """

    fact_id: str = Field(
        description="Устойчивый идентификатор, например BAN-1",
    )
    kind: str = Field(
        description=(
            "Вид факта пополняемого источника. Формат: ^[a-z][a-z0-9_]{2,63}$ "
            "или один из CORE_FACT_KINDS"
        ),
    )
    statement: str = Field(description="Утверждение на естественном языке")
    source_url: str = Field(description="Ссылка на первоисточник")
    source_type: str = Field(
        description="Тип источника: registry_api, court, news, custom",
    )
    trust: Literal["registry", "reference", "mention"] = Field(
        default="mention",
        description=(
            "Ступень доверия источника: registry — факт как факт; "
            "reference — подтверждает реестровый факт; mention — просто "
            "упоминание. По умолчанию минимум"
        ),
    )
    retrieved_at: datetime = Field(description="Когда получено")
    event_date: date | None = Field(
        default=None,
        description="Дата самого события, не публикации",
    )
    payload: dict = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _kind_format(cls, v: str) -> str:
        if not is_valid_ext_kind(v):
            raise ValueError(
                f"kind «{v}» не соответствует формату ^[a-z][a-z0-9_]{{2,63}} "
                f"и не входит в ядро {sorted(CORE_FACT_KINDS)}"
            )
        return v


class Fact(BaseModel):
    """Единица знания о компании.

    Ключевое требование проекта: у каждого факта есть проверяемый источник.
    Утверждение, не опирающееся на факт с валидным fact_id, вырезается
    из итогового отчёта автоматически.
    """

    fact_id: str = Field(
        description="Устойчивый идентификатор для ссылки из текста, например ARB-1"
    )
    kind: FactKind = Field(description="Категория факта")
    statement: str = Field(description="Утверждение на естественном языке")
    source_url: str = Field(
        description="Ссылка на первоисточник. Без неё факт не существует"
    )
    source_type: str = Field(description="Тип источника: registry_api, court, news")
    retrieved_at: datetime = Field(description="Когда получено")
    event_date: date | None = Field(
        default=None,
        description="Дата САМОГО СОБЫТИЯ, а не публикации о нём. В оценку риска идёт она",
    )
    payload: dict = Field(
        default_factory=dict, description="Структурированные данные факта"
    )


class RoleCounts(BaseModel):
    """Счётчики в разрезе роли — процессуальной в суде, стороны в контракте."""

    count: int = Field(default=0, description="Количество записей в этой роли")
    total_amount: float = Field(
        default=0.0, description="Суммарная сумма по этой роли, рублей"
    )


class ArbitrationSummary(BaseModel):
    """Арбитражные дела в сжатом виде.

    Роль важнее суммы: ответчик на 50 млн и истец на 50 млн — противоположные
    сигналы. Источник отдаёт общую сумму без разделения по роли, поэтому
    разделение считается здесь.
    """

    total: int = Field(default=0, description="Всего дел в базе источника")
    total_claim_amount: float = Field(
        default=0.0,
        description="Общая цена исков по ВСЕМ делам, из агрегата источника, БЕЗ разделения по роли",
    )
    as_defendant: RoleCounts = Field(
        default_factory=RoleCounts,
        description="Компания ОТВЕТЧИК — к ней предъявлены требования. Тревожный признак",
    )
    as_plaintiff: RoleCounts = Field(
        default_factory=RoleCounts,
        description="Компания ИСТЕЦ — она сама взыскивает. Обычно не является риском",
    )
    as_plaintiff_active: RoleCounts = Field(
        default_factory=RoleCounts,
        description=(
            "Компания ИСТЕЦ в активной стадии дел. Систематические новые иски "
            "о взыскании оплаты — косвенный признак того, что ей сами не "
            "платят: кассовый разрыв у контрагента начинается с его дебиторов"
        ),
    )
    as_both: RoleCounts = Field(
        default_factory=RoleCounts,
        description=(
            "Компания числится И истцом, И ответчиком в одном деле: встречный иск "
            "либо участие её обособленного подразделения. Требования к ней есть, "
            "поэтому трактуй ближе к роли ответчика, но не смешивай с ним"
        ),
    )
    other_participation: int = Field(
        default=0,
        description=(
            "Дел, где ИНН компании не встретился ни в истцах, ни в ответчиках: "
            "участие третьим лицом либо под другим идентификатором"
        ),
    )
    roles_counted_from: int = Field(
        default=0,
        description=(
            "По СКОЛЬКИМ делам посчитана разбивка по ролям. У организаций с "
            "тысячами дел выгрузить все невозможно, поэтому разбивка строится "
            "по выборке. Если это число меньше total — разбивка НЕПОЛНАЯ"
        ),
    )
    roles_complete: bool = Field(
        default=True, description="Охвачены ли разбивкой все дела"
    )
    active_cases: int = Field(default=0, description="Дел в активной стадии (в выборке)")
    last_case_date: date | None = Field(default=None, description="Дата последнего дела")


class EnforcementSummary(BaseModel):
    """Исполнительные производства ФССП: долги, которые уже взыскивают."""

    total: int = Field(default=0, description="Всего производств")
    total_amount: float = Field(default=0.0, description="Общая сумма, рублей")
    outstanding: float = Field(default=0.0, description="Непогашенный остаток, рублей")


class PlannedInspection(BaseModel):
    """Предстоящая или текущая проверка надзорного органа (ЕРКНМ)."""

    number: str | None = Field(default=None, description="Номер проверки в ЕРКНМ")
    authority: str = Field(description="Контролирующий орган (МЧС, Роструд, Роспотребнадзор и др.)")
    date_start: date | None = Field(default=None, description="Планируемая дата начала")
    inspection_type: str | None = Field(default=None, description="Тип проверки (плановая, внеплановая, визит)")
    purpose: str | None = Field(default=None, description="Цель проверки")


class InspectionSummary(BaseModel):
    """Проверки надзорных органов."""

    total: int = Field(default=0, description="Всего проверок в базе источника")
    with_violations: int = Field(
        default=0, description="Из просмотренных — сколько выявили нарушения"
    )
    planned_inspections: list[PlannedInspection] = Field(
        default_factory=list, description="Предстоящие и плановые проверки (ЕРКНМ)"
    )
    counted_from: int = Field(default=0, description="По скольким проверкам посчитано")
    complete: bool = Field(default=True, description="Охвачены ли все проверки")


class ProcurementSummary(BaseModel):
    """Регулируемые закупки: 44-ФЗ и 223-ФЗ.

    Роль в контракте меняет смысл на противоположный, ровно как
    процессуальная роль в судебном деле. Поставщик — исполнитель заказа,
    это опыт. Заказчик — тот, кто закупает сам; для организации это
    признак государственного участия, а не выигранных подрядов.
    """

    contracts_44: int = Field(default=0, description="Контрактов по 44-ФЗ")
    contracts_223: int = Field(default=0, description="Контрактов по 223-ФЗ")
    as_supplier: RoleCounts = Field(
        default_factory=lambda: RoleCounts(),
        description=(
            "Контракты, где организация ИСПОЛНИТЕЛЬ. Это опыт работы "
            "по государственному и регулируемому заказу"
        ),
    )
    as_customer: RoleCounts = Field(
        default_factory=lambda: RoleCounts(),
        description=(
            "Контракты, где организация САМА ЗАКУПАЕТ. Это НЕ выигранные "
            "подряды: заказчиками по 223-ФЗ выступают госкорпорации, "
            "компании с госучастием, естественные монополии, ГУП и МУП"
        ),
    )
    other_participation: int = Field(
        default=0,
        description="Контракты, где ИНН организации не найден ни в одной стороне",
    )
    roles_counted_from: int = Field(
        default=0, description="По скольким контрактам разобраны роли"
    )
    roles_complete: bool = Field(
        default=True,
        description="False — роли разобраны по выборке, а не по всем контрактам",
    )
    total_amount: float = Field(
        default=0.0,
        description=(
            "Сумма по просмотренным контрактам БЕЗ разделения ролей. "
            "НЕ выдавай её за объём выигранных подрядов"
        ),
    )
    counted_from: int = Field(default=0, description="По скольким контрактам посчитано")
    complete: bool = Field(default=True, description="Охвачены ли все контракты")


class FinancialSummary(BaseModel):
    """Финансовое состояние — нужно для калибровки оценки риска.

    Набор значимых признаков различается для крупного бизнеса и малого:
    массовый адрес у крупной компании невозможен, а у однодневки решает.
    """

    years: list[FinancialYear] = Field(
        default_factory=list, description="Показатели по годам, свежие первыми"
    )
    employees: int | None = Field(default=None, description="Среднесписочная численность")
    branches: int | None = Field(
        default=None, description="Сколько филиалов. None — не установлено"
    )
    representative_offices: int | None = Field(
        default=None, description="Сколько представительств. None — не установлено"
    )
    capital: float | None = Field(
        default=None,
        description=(
            "Уставный капитал, рублей. Для микро- и малого бизнеса минимальный "
            "капитал — заметный признак; для крупного значения не имеет"
        ),
    )
    size_category: Literal["micro", "small", "medium", "large", "unknown"] = Field(
        default="unknown",
        description=(
            "Категория по выручке и численности. Определяет, какие признаки "
            "риска вообще применимы к организации"
        ),
    )
    extras: CardExtras | None = Field(
        default=None,
        description="Налоги, лицензии, контакты, массовость адреса — из той же карточки",
    )


class PersonProfile(BaseModel):
    """Сведения о физическом лице — руководителе или учредителе.

    Риски по человеку часто весомее корпоративных: проблемный руководитель
    переносит практику из компании в компанию.
    """

    inn: str | None = Field(default=None, description="ИНН физического лица")
    fio: str | None = Field(default=None, description="ФИО")
    role_in_company: str | None = Field(
        default=None, description="Кем является в проверяемой организации"
    )
    share_percent: float | None = Field(
        default=None,
        description=(
            "Доля в уставном капитале, проценты. Владелец 78% и владелец 5% "
            "влияют на компанию несопоставимо — не описывай их одинаково"
        ),
    )
    manages_count: int = Field(
        default=0, description="Сколько организаций возглавляет, включая проверяемую"
    )
    owns_count: int = Field(
        default=0, description="Сколько организаций учредил, включая проверяемую"
    )
    checked: bool = Field(
        default=True,
        description=(
            "Удалось ли проверить человека. False — ИНН в реестре не указан "
            "либо источник не ответил: личные риски НЕ ПРОВЕРЕНЫ, "
            "а не отсутствуют"
        ),
    )
    not_checked_reason: str | None = Field(
        default=None, description="Почему человек не проверен. Заполняется при checked=False"
    )
    sole_proprietor: bool = Field(default=False, description="Имеет статус ИП")
    personal_bankruptcy: bool = Field(
        default=False, description="Есть сведения о личном банкротстве"
    )
    mass_manager: bool = Field(default=False, description="Признан массовым руководителем")
    mass_founder: bool = Field(default=False, description="Признан массовым учредителем")
    unfair_supplier: bool = Field(default=False, description="В реестре недобросовестных поставщиков")
    sanctioned: bool = Field(default=False, description="В санкционных списках")
    unreliable: bool = Field(
        default=False,
        description="ФНС признала сведения об этом лице недостоверными",
    )
    disqualified: bool = Field(
        default=False, description="Дисквалифицирован, запрещено руководить организациями"
    )


class RelatedCompany(BaseModel):
    """Организация, связанная с проверяемой через людей или владельцев.

    Здесь собрано и то, как связь найдена, и то, что удалось про эту
    организацию выяснить. Голый ИНН бесполезен: без названия и статуса
    читатель отчёта не поймёт, что перед ним.
    """

    inn: str | None = Field(default=None, description="ИНН связанной организации")
    ogrn: str | None = Field(default=None, description="ОГРН, если ИНН неизвестен")
    name: str | None = Field(default=None, description="Краткое наименование")
    status: str | None = Field(
        default=None,
        description=(
            "Состояние в реестре. Значение, отличное от «Действует» — "
            "ликвидация, исключение по решению ФНС — существенный признак"
        ),
    )
    registered_at: date | None = Field(default=None, description="Дата регистрации")
    okved_text: str | None = Field(default=None, description="Основной вид деятельности")
    link: str = Field(
        description=(
            "Как найдена связь: через руководителя, учредителя, "
            "владельца-организацию, управляющую организацию или реорганизацию"
        )
    )
    via: str | None = Field(
        default=None, description="Через кого именно — ФИО человека или название организации"
    )
    triage_status: str = Field(
        default="not_checked",
        description=(
            "checked — карточка получена, отметки достоверны; "
            "unavailable — источник не ответил, риски НЕ ПРОВЕРЕНЫ; "
            "not_checked — до организации не дошла очередь из-за лимита"
        ),
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Сработавшие отметки: банкротство, санкции, РНП, массовость и прочие",
    )
    suspicious: bool = Field(
        default=False,
        description=(
            "Организация прошла триаж и требует внимания: недействующий статус, "
            "поднятая отметка или сообщения о банкротстве"
        ),
    )
    deep_summary: str | None = Field(
        default=None,
        description=(
            "Итог полной проверки: суды, приставы, надзор. Заполняется только "
            "для подозрительных организаций"
        ),
    )
    source_url: str | None = Field(default=None, description="Карточка организации")


class AffiliationGraph(BaseModel):
    """Связи организации через людей, владельцев и реорганизацию.

    Смысл: сама организация может быть безупречной, а её владелец —
    держать рядом проблемное юрлицо. Проверка одной компании этого
    не покажет никогда, потому что общего идентификатора у них нет.
    """

    inn: str = Field(description="ИНН проверяемой организации")
    people: list[PersonProfile] = Field(
        default_factory=list, description="Руководители и учредители — физические лица"
    )
    owner_organizations: list[RelatedCompany] = Field(
        default_factory=list,
        description="Владельцы-организации и управляющая организация",
    )
    predecessors: list[RelatedCompany] = Field(
        default_factory=list,
        description=(
            "Правопредшественники: организации, из которых эта возникла "
            "при реорганизации. У них другой ИНН, и прошлое тянется оттуда"
        ),
    )
    successors: list[RelatedCompany] = Field(
        default_factory=list,
        description="Правопреемники: организации, в которые эта перешла",
    )
    related_companies: list[RelatedCompany] = Field(
        default_factory=list,
        description="Иные организации, связанные через людей и владельцев",
    )
    suspicious_count: int = Field(
        default=0, description="Сколько связанных организаций вызвали подозрение"
    )
    shareholders_undisclosed: bool = Field(
        default=False,
        description=(
            "Организация — акционерное общество, состав владельцев в реестре "
            "НЕ РАСКРЫВАЕТСЯ. Пустой список владельцев здесь означает "
            "невозможность проверки, а не отсутствие собственников"
        ),
    )
    coverage_note: str | None = Field(
        default=None,
        description=(
            "Чего проверка НЕ охватила: упор в лимит, неответивший источник, "
            "нераскрытые акционеры. Обязательно передай пользователю"
        ),
    )


class BrandInfo(BaseModel):
    """Рыночное наименование компании.

    Ключевое для веб-поиска: в реестре организация записана как
    'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"', а в публикациях
    её называют иначе. Поиск по юридическому наименованию не найдёт ничего.
    """

    resolved: bool = Field(description="Удалось ли установить рыночное наименование")
    brand: str | None = Field(default=None, description="Рыночное наименование")
    domain: str | None = Field(default=None, description="Официальный сайт")
    summary: str | None = Field(default=None, description="Описание деятельности")
    social_links: dict[str, str] = Field(
        default_factory=dict, description="Ссылки на официальные аккаунты"
    )
    reason: str | None = Field(
        default=None, description="Почему не удалось, если resolved=False"
    )


class SourceResult(BaseModel):
    """Результат обращения к одному источнику.

    Инструмент никогда не возвращает голый список фактов. Пустой список без
    статуса читается и человеком, и моделью как «нарушений нет» — то есть
    отсутствие данных молча превращается в положительное заключение.
    Это худший вид ошибки в системе оценки рисков.
    """

    source: str = Field(description="Идентификатор источника")
    status: SourceStatus = Field(
        description=(
            "ok — источник ответил; unavailable — не ответил, выводы делать нельзя; "
            "partial — ответил частично; skipped — не опрашивался"
        )
    )
    reason: str | None = Field(default=None, description="Причина, если status не 'ok'")
    facts: list[Fact] = Field(default_factory=list, description="Полученные факты")
    arbitration: ArbitrationSummary | None = Field(default=None)
    enforcement: EnforcementSummary | None = Field(default=None)
    inspections: InspectionSummary | None = Field(default=None)
    procurement: ProcurementSummary | None = Field(default=None)
    flags: dict[str, bool] = Field(
        default_factory=dict, description="Реестровые отметки: признак -> установлен ли"
    )


class RiskCollection(BaseModel):
    """Сводный результат всех реестровых проверок.

    Собирается за одно обращение: каждое обращение агента к инструменту
    требует отдельного прогона языковой модели, и пять последовательных
    вызовов обходятся в пять таких прогонов.

    Истолкования здесь нет — только исходные факты. Оценка риска
    вычисляется отдельно и детерминированно.
    """

    inn: str = Field(description="ИНН проверенной организации")
    results: list[SourceResult] = Field(description="Результаты по каждому источнику")
    facts: list[Fact] = Field(
        default_factory=list, description="Все факты одним списком, для ссылок из текста"
    )
    sources_ok: int = Field(default=0, description="Сколько источников ответило")
    sources_failed: int = Field(default=0, description="Сколько не ответило")
    coverage_note: str | None = Field(
        default=None,
        description=(
            "Заполняется, если часть источников недоступна. Обязательно передать "
            "пользователю: проверка неполная, отсутствие находок ничего не доказывает"
        ),
    )


class ContextResult(BaseModel):
    """Обёртка над контекстом с явным статусом источника.

    Инструмент никогда не возвращает голый контекст: «источник недоступен»
    обязано структурно отличаться от «данных нет».
    """

    status: SourceStatus = Field(description="Состояние источника")
    reason: str | None = Field(
        default=None,
        description=(
            "Чего собрать НЕ УДАЛОСЬ. Заполняется И ПРИ status='ok': карточка "
            "собирается из двух служб, и отказ второй не отменяет результат, "
            "но оставляет поля пустыми. Пустое поле при непустом reason "
            "означает «не смогли получить», а НЕ «сведений не существует». "
            "Обязательно передай содержание пользователю"
        ),
    )
    context: CompanyContext | None = Field(default=None, description="Контекст компании")


# ──────────────────────────  Полнота проверки  ──────────────────────────

class ServiceUsage(BaseModel):
    """Сколько обращений израсходовано к одной службе."""

    service: str = Field(description="Служба-источник")
    requests: int = Field(description="Обращений по этой организации")
    ok: int = Field(default=0, description="Из них вернули данные")
    empty: int = Field(default=0, description="Ответили, но данных нет")
    failed: int = Field(default=0, description="Не ответили")
    daily_spent: int | None = Field(
        default=None,
        description=(
            "Израсходовано по ключу за сутки — по данным самой службы. "
            "Счётчик общий на ключ и включает обращения по другим "
            "организациям, а не только по этой. null — служба такого "
            "счётчика не сообщает; это НЕ ноль"
        ),
    )


class DataGap(BaseModel):
    """Чего не получили и по какой причине.

    Причина существеннее самого факта отсутствия: «источник молчал»
    и «сведений действительно нет» ведут к противоположным выводам.
    """

    what: str = Field(description="Какие сведения отсутствуют")
    kind: Literal["source_failed", "not_requested", "no_data", "not_implemented"] = Field(
        description=(
            "source_failed — источник не ответил, ПРОВЕРКА НЕ СОСТОЯЛАСЬ; "
            "not_requested — проверку не запускали; "
            "no_data — проверка прошла, сведений действительно нет; "
            "not_implemented — направление в системе пока не реализовано"
        )
    )
    reason: str | None = Field(default=None, description="Подробность отказа")


class CoverageReport(BaseModel):
    """Отчёт о полноте проверки конкретной организации."""

    inn: str = Field(description="ИНН, по которому собран отчёт")
    checked: bool = Field(
        description=(
            "Были ли вообще обращения по этой организации. False — проверка "
            "не проводилась, и делать выводы не о чем"
        )
    )
    total_requests: int = Field(default=0, description="Всего обращений по организации")
    services: list[ServiceUsage] = Field(
        default_factory=list, description="Расход по каждой службе"
    )
    methods_ok: list[str] = Field(
        default_factory=list, description="Направления, вернувшие данные"
    )
    methods_failed: list[str] = Field(
        default_factory=list, description="Направления, не ответившие"
    )
    obtained: list[str] = Field(
        default_factory=list, description="Какие сведения удалось собрать"
    )
    gaps: list[DataGap] = Field(
        default_factory=list, description="Чего собрать не удалось и почему"
    )
    session_requests: dict[str, int] = Field(
        default_factory=dict,
        description="Обращений с момента запуска сервера, по службам — по всем организациям",
    )


class KeyStatus(BaseModel):
    """Статус отдельного ключа из пула."""

    key: str = Field(description="Маскированный хвост ключа (например, …1234)")
    state: Literal["ok", "exhausted"] = Field(description="Состояние: ok или exhausted")


class ServiceQuota(BaseModel):
    """Суточный расход и остаток запросов конкретного метода сервиса."""

    used: int = Field(default=0, description="Израсходовано запросов за сутки")
    remaining: int = Field(default=0, description="Осталось запросов в суточной квоте")


class ProviderLimit(BaseModel):
    """Сведения о лимитах и состоянии ключей конкретного провайдера."""

    provider: str = Field(description="Кодовое имя (dadata, checko, apicloud, hh, bo_nalog, egrul, etc.)")
    name: str = Field(description="Понятное название сервиса")
    status: Literal["ok", "warning", "exhausted", "not_configured", "unlimited"] = Field(
        description="Статус доступности сервиса: ok, warning, exhausted, not_configured, unlimited"
    )
    category: str = Field(
        default="commercial",
        description="Категория: commercial (платный API), official_registry (госреестр), osint_web (веб-разведка), aggregator (резервный шлюз)"
    )
    keys_total: int = Field(default=0, description="Всего ключей в пуле")
    keys_active: int = Field(default=0, description="Число активных неизрасходованных ключей")
    keys: list[KeyStatus] = Field(default_factory=list, description="Статус каждого ключа пула")
    daily_limit_per_key: int | None = Field(
        default=None, description="Базовый суточный лимит запросов на 1 ключ"
    )
    pool_daily_capacity: int | None = Field(
        default=None, description="Суммарная суточная ёмкость пула ключей (запросов в день)"
    )
    daily_spent: int | None = Field(
        default=None, description="Израсходовано за сутки по данным службы или локального учёта"
    )
    session_spent: int = Field(
        default=0, description="Израсходовано запросов в текущей сессии"
    )
    estimated_remaining_requests: int | None = Field(
        default=None, description="Расчётный остаток доступных запросов на сегодня"
    )
    cost_per_company_requests: int = Field(
        default=1, description="Средний расход запросов данного сервиса на одну проверку компании"
    )
    estimated_companies_remaining: int | None = Field(
        default=None, description="Расчётное число компаний, на которое хватит оставшихся лимитов"
    )
    methods: dict[str, ServiceQuota] = Field(
        default_factory=dict, description="Расход и остаток по отдельным методам API"
    )
    notes: str | None = Field(default=None, description="Пояснения к тарифу или ограничениям")
    error: str | None = Field(default=None, description="Текст ошибки при запросе статистики, если была")


class ProvidersLimitsReport(BaseModel):
    """Сводный отчёт по лимитам, суточным квотам и ключам всех провайдеров."""

    summary: dict = Field(
        default_factory=dict,
        description="Сводная статистика: общая ёмкость, активные ключи, доступный запас проверок"
    )
    providers: list[ProviderLimit] = Field(
        default_factory=list, description="Состояние лимитов по каждому провайдеру"
    )
    alerts: list[str] = Field(
        default_factory=list, description="Предупреждения о низком остатке квоты или проблемах с ключами"
    )
    checked_at: datetime = Field(
        description="Время выполнения проверки (UTC)"
    )

