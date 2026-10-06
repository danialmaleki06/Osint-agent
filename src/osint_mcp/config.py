"""Настройки. Ключи читаются из окружения либо из .env, в код не попадают."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dadata_api_key: str = Field(default="", description="Ключ DaData")
    # Список ключей через запятую — пул на случай суточного лимита.
    dadata_api_keys: str = Field(
        default="", description="Список ключей DaData через запятую (пул)"
    )
    dadata_secret_key: str = Field(
        default="", description="Секретный ключ DaData — нужен только для метода бренда"
    )
    checko_api_key: str = Field(default="", description="Ключ Checko")
    # Список ключей через запятую — пул на случай суточного лимита.
    checko_api_keys: str = Field(
        default="", description="Список ключей Checko через запятую (пул)"
    )

    @field_validator("dadata_api_keys", "checko_api_keys", mode="after")
    @classmethod
    def _allow_list(cls, v: str) -> str:
        """Принять и формат с несколькими ключами, и JSON-список."""
        s = (v or "").strip()
        if s.startswith("[") and s.endswith("]"):
            import json

            try:
                return ",".join(str(x) for x in json.loads(s))
            except ValueError:
                return s
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
    cache_ttl_hours: int = Field(default=24, description="Срок жизни кэша реестровых данных")

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

    def require(self, name: str) -> str:
        """Достать ключ или упасть с внятным сообщением, а не с пустой строкой."""
        value = getattr(self, name, "")
        if not value:
            raise RuntimeError(
                f"Не задан {name.upper()}. Скопируйте .env.example в .env "
                f"и впишите ключ."
            )
        return value


settings = Settings()
