"""Настройки. Ключи читаются из окружения либо из .env, в код не попадают."""

from ipaddress import IPv4Address
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dadata_api_key: str = Field(default="", description="Ключ DaData")
    dadata_api_keys: str = Field(
        default="", description="Список ключей DaData через запятую (пул)"
    )
    dadata_secret_key: str = Field(
        default="", description="Секретный ключ DaData — нужен только для метода бренда"
    )
    checko_api_key: str = Field(default="", description="Ключ Checko")
    checko_api_keys: str = Field(
        default="", description="Список ключей Checko через запятую (пул)"
    )

    @field_validator("dadata_api_keys", "checko_api_keys", mode="after")
    @classmethod
    def _allow_list(cls, v: str) -> str:
        """Принять и формат с несколькими ключами, и JSON-список."""
        s = (v or "").strip()
        if s.startswith("["):
            import json

            try:
                parsed = json.loads(s)
            except json.JSONDecodeError as exc:
                raise ValueError("Ожидается корректный JSON-массив строк") from exc

            if not isinstance(parsed, list) or not all(
                isinstance(item, str) for item in parsed
            ):
                raise ValueError("Список API-ключей должен быть JSON-массивом строк")

            return ",".join(item.strip() for item in parsed if item.strip())
        return s

    def dadata_key_pool(self) -> list[str]:
        """Ключи DaData: сначала список, затем одиночный формат."""
        keys = [k.strip() for k in self.dadata_api_keys.split(",") if k.strip()]
        return keys or ([self.dadata_api_key] if self.dadata_api_key else [])

    def checko_key_pool(self) -> list[str]:
        """Ключи Checko: сначала список, затем одиночный формат."""
        keys = [k.strip() for k in self.checko_api_keys.split(",") if k.strip()]
        return keys or ([self.checko_api_key] if self.checko_api_key else [])

    dadata_base_url: str = "https://suggestions.dadata.ru/suggestions/api/4_1/rs"
    dadata_brand_url: str = "https://api.dadata.ru/findById/brand"
    dadata_stat_url: str = "https://dadata.ru/api/v2/stat/daily"
    checko_base_url: str = "https://api.checko.ru/v2"

    # ── бесплатные официальные источники (без ключей и квот) ──────────
    # ГИР БО — бухгалтерская отчётность ФНС; rmsp — реестр субъектов МСП;
    # egrul — сведения ЕГРЮЛ напрямую. Работают без ключей, поэтому
    # финансы и подтверждение масштаба доступны даже при исчерпанных
    # квотах платных справочников.
    bo_nalog_base_url: str = "https://bo.nalog.gov.ru"
    rmsp_base_url: str = "https://rmsp.nalog.ru"
    registry_proxy_url: str | None = Field(
        default=None, validation_alias="OSINT_REGISTRY_PROXY_URL"
    )
    registry_bind_ipv4: IPv4Address | None = Field(
        default=None, validation_alias="OSINT_REGISTRY_BIND_IPV4"
    )

    @field_validator("registry_bind_ipv4", mode="before")
    @classmethod
    def _normalize_registry_address(cls, value):
        return value.strip() or None if isinstance(value, str) else value

    @field_validator("registry_proxy_url")
    @classmethod
    def _normalize_registry_proxy(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    hh_base_url: str = "https://api.hh.ru"
    # Бесплатный токен приложения dev.hh.ru: без него API вакансий
    # отвечает 403. Пусто — источник честно помечается недоступным.
    hh_app_token: str = Field(
        default="", description="Токен приложения HeadHunter для поиска вакансий"
    )
    egrul_base_url: str = "https://egrul.nalog.ru"
    # Федресурс — коммерческие сведения: лизинг, залоги, факторинг,
    # гарантии, СРО. Бесплатный официальный источник, ключей не требует.
    fedresurs_base_url: str = "https://fedresurs.ru"

    # ── резервный эшелон: агрегатор api-cloud.ru ─────────────────────
    # Подключается, когда платный канал по судам или приставам молчит.
    # Бесплатный тариф — около 200 запросов в месяц, поэтому резерв
    # дёргается только при реальном отказе прямого источника.
    apicloud_base_url: str = "https://api-cloud.ru/api"
    apicloud_key: str = Field(
        default="", description="Персональный ключ api-cloud.ru (резервные источники)"
    )

    request_timeout: float = Field(default=8.0, description="Таймаут запроса, секунды")
    yandex_search_api_key: str = Field(default="", validation_alias="YANDEX_SEARCH_API_KEY")
    yandex_search_folder_id: str = Field(default="", validation_alias="YANDEX_SEARCH_FOLDER_ID")
    yandex_search_mode: Literal["fallback", "disabled", "primary"] = Field(
        default="fallback", validation_alias="YANDEX_SEARCH_MODE",
        description="fallback — платный резерв после отказа бесплатных источников; disabled — без Яндекса",
    )
    yandex_search_budget_rub: float = Field(
        default=4.0, ge=0, le=4.0, allow_inf_nan=False, validation_alias="YANDEX_SEARCH_BUDGET_RUB",
        description="Максимальный бюджет Яндекса на одно досье; от 0 до 4 рублей",
    )
    cache_ttl_hours: int = Field(default=24, description="Срок жизни кэша реестровых данных")
    osint_debug: bool = Field(
        default=False,
        validation_alias="OSINT_DEBUG",
        description="Режим отладки: выводить диагностику недоступных источников и технические детали",
    )
    human_friendly_mode: bool = Field(
        default=True,
        validation_alias="OSINT_HUMAN_MODE",
        description="Человеческий язык отчёта: понятные формулировки, TL;DR-резюме и сюжетные карточки вместо канцелярита и аббревиатур",
    )
    expose_granular_tools: bool = Field(
        default=False,
        validation_alias="OSINT_EXPOSE_GRANULAR_TOOLS",
        description="Экспортировать ли низкоуровневые промежуточные инструменты в MCP-реестр (по умолчанию false)",
    )

    # Списочные методы Checko и Федресурса отдают записи постранично. У крупных
    # организаций страниц бывают тысячи — выкачать всё нельзя. Берём первые
    # страницы и честно сообщаем, по какой доле посчитана разбивка.
    max_pages: int = Field(default=3, description="Сколько страниц тянуть из списочных методов")

    # Обход связей растёт лавинообразно: у массового учредителя бывают
    # десятки компаний, у каждой — свои люди. Без потолков одно досье
    # способно съесть суточную квоту. Потолки заданы явно, а их достижение
    # обязано попадать в ответ: молча обрезанный граф выглядит как полный.
    affiliation_max_people: int = Field(
        default=10, description="Сколько физлиц опрашивать по организации"
    )
    affiliation_max_related: int = Field(
        default=30, description="Сколько связанных организаций проверять поверхностно"
    )
    affiliation_max_deep: int = Field(
        default=5, description="Сколько подозрительных организаций проверять полностью"
    )

    # ── удалённый режим ─────────────────────────────────────────────
    # Ключи к платным справочникам лежат на сервере. Открытый адрес без
    # проверки — это возможность для любого, кто его узнает, расходовать
    # нашу квоту. Поэтому в сетевом режиме токен обязателен, и сервер
    # без него не поднимается: молча работающий незащищённый сервер
    # опаснее, чем не запустившийся.
    # Имена переменных заданы явно: транспорт читается как
    # OSINT_MCP_TRANSPORT, и остальные настройки сетевого режима обязаны
    # называться так же. Иначе сообщение об ошибке советует одно имя,
    # а код читает другое — на этом я уже споткнулся.
    mcp_transport: str = Field(default="stdio", validation_alias="OSINT_MCP_TRANSPORT")
    mcp_token: str = Field(
        default="", validation_alias="OSINT_MCP_TOKEN",
        description="Токен доступа для сетевого режима",
    )
    http_host: str = Field(
        default="127.0.0.1", validation_alias="OSINT_MCP_HOST",
        description="Адрес прослушивания",
    )
    http_port: int = Field(
        default=8000, validation_alias="OSINT_MCP_PORT",
        description="Порт прослушивания",
    )
    # SDK по умолчанию принимает запросы только на localhost: это защита
    # от подмены адреса, когда чужая страница в браузере обращается
    # к серверу на вашей машине. За туннелем заголовок Host содержит
    # публичный домен, и без этого списка сервер отвечает отказом 421.
    # Токен при этом остаётся главной защитой — список лишь разрешает домен.
    mcp_allowed_hosts: str = Field(
        default="", validation_alias="OSINT_MCP_ALLOWED_HOSTS",
        description="Домены через запятую, с которых принимать запросы",
    )

    def allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.mcp_allowed_hosts.split(",") if h.strip()]


settings = Settings()
