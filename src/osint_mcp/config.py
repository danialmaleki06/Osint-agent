"""Настройки. Ключи читаются из окружения либо из .env, в код не попадают."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dadata_api_key: str = Field(default="", description="Ключ DaData")
    dadata_secret_key: str = Field(
        default="", description="Секретный ключ DaData — нужен только для метода бренда"
    )
    checko_api_key: str = Field(default="", description="Ключ Checko")

    dadata_base_url: str = "https://suggestions.dadata.ru/suggestions/api/4_1/rs"
    dadata_brand_url: str = "https://api.dadata.ru/findById/brand"
    dadata_stat_url: str = "https://dadata.ru/api/v2/stat/daily"
    checko_base_url: str = "https://api.checko.ru/v2"

    request_timeout: float = Field(default=8.0, description="Таймаут запроса, секунды")
    cache_ttl_hours: int = Field(default=24, description="Срок жизни кэша реестровых данных")

    # Списочные методы Checko отдают по 100 записей на страницу. У крупных
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
