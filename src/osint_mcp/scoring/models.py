"""Модели скоринга.

Скоринг детерминирован: критерии и веса живут в config_data/scoring.yaml,
здесь только результат и его разбор. Никакого ИИ — пересказ посчитанного
делает агент, а не движок.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

VerdictLabel = Literal[
    "отлично", "хорошо", "удовлетворительно",
    "рискованно", "не рекомендуется",
]


class MatchedCriterion(BaseModel):
    """Один сработавший критерий с доказательной базой."""

    criterion: str = Field(description="Имя критерия из scoring.yaml")
    group: str = Field(description="Группа критерия")
    description: str = Field(default="", description="Описание критерия")
    score: float = Field(description="Балл с учётом затухания и веса группы")
    raw_value: float | None = Field(
        default=None,
        description="Агрегированное значение (сумма, количество, возраст)",
    )
    fact_ids: list[str] = Field(
        description="ID фактов, на которых сработал критерий",
    )
    source_urls: list[str] = Field(
        description="Первоисточники — каждый вердикт доказуем",
    )
    reason: str = Field(
        default="",
        description="Краткая причина по шаблону из критерия",
    )


class GroupScore(BaseModel):
    """Вклад одной группы в итог."""

    group: str
    weight: float = Field(description="Нормированный вес группы, %")
    score: float = Field(description="Сумма баллов сработавших критериев группы")
    weighted: float = Field(description="Вклад в итог с учётом веса")


class Verdict(BaseModel):
    """Итоговая оценка."""

    label: VerdictLabel = Field(description="Оценка по шкале")
    total_score: float = Field(description="Суммарный балл до вердикта")
    floored: bool = Field(
        default=False,
        description=(
            "True — вердикт понижен жёстким полом (verdict_floor): "
            "балл выглядел лучше, но сработал запретительный критерий"
        ),
    )
    floor_criterion: str | None = Field(
        default=None,
        description="Какой критерий урезал вердикт (если floored)",
    )


class PendingFact(BaseModel):
    """Факт на карантине: найден, но в скоринг не попадает.

    Из реестровых источников факты приходят подтверждёнными. Из внешних
    (поиск, парсинг сайтов) — нет: там находка может быть мусором или
    омонимом. Такой факт виден в досье с ссылкой на первоисточник,
    но вердикт не двигает — ни минусом, ни плюсом. Решение о переводе
    в скоринг — за человеком или явным правилом.
    """

    fact_id: str = Field(description="Идентификатор, например SRCH-1")
    kind: str = Field(description="Вид факта, например dog_connection")
    statement: str = Field(description="Что нашлось, на естественном языке")
    source_url: str = Field(
        description=(
            "Ссылка на страницу-первоисточник. Обязательна ВСЕГДА: "
            "данные не из реестра без ссылки не существуют"
        ),
    )
    found_by: str = Field(
        description="Кто нашёл: идентификатор адаптера, например web_search",
    )
    trust: Literal["reference", "mention"] = Field(
        default="mention",
        description="mention — просто упоминание; reference — подтверждает другой факт",
    )
    found_at: datetime = Field(description="Когда найдено")

    @field_validator("source_url")
    @classmethod
    def _url_required(cls, v: str) -> str:
        if not v.strip():
            raise ValueError(
                "Карантинный факт без ссылки не существует: добавь source_url "
                "на страницу-первоисточник"
            )
        return v


class PendingReview(BaseModel):
    """Подтверждение находки агентом — это ПОДСКАЗКА, не вердикт.

    Агент сам выставляет вес (насколько находка влияет на решение о
    сотрудничестве), но обязан показать его рядом со ссылкой на
    первоисточник: пользователь видит сырьё, составляет мнение сам и
    может не согласиться. Честность держится не на запрете агенту
    оценивать, а на том, что его оценка всегда проверяема по ссылке.
    """

    fact: PendingFact
    weight: float = Field(
        description="Оценка агента: насколько находка влияет на решение",
    )
    rationale: str = Field(
        description="Почему такой вес — краткое объяснение, показывается рядом со ссылкой",
    )
    confirmed_by: Literal["agent", "human"] = Field(
        default="agent",
        description="agent — подсказка ИИ; human — человек переоценил сам",
    )


class SearchUnverifiedResult(BaseModel):
    """Результат веб-поиска: всё в карантин, вердикт не тронут."""

    inn: str
    query: str
    found: int = Field(description="Сколько находок вернул поиск")
    added_to_quarantine: int = Field(
        description="Сколько из них записано в карантин (новые)",
    )
    hits: list[PendingFact] = Field(
        description="Сами находки — каждая с source_url",
    )
    note: str = Field(description="Пояснение к результатам поиска")


class ScoreResult(BaseModel):
    """Полный результат оценки организации."""

    inn: str
    verdict: Verdict
    groups: list[GroupScore]
    matched: list[MatchedCriterion] = Field(
        description="Все сработавшие критерии с фактами и источниками",
    )
    reasons: list[str] = Field(
        description="Краткие причины. Пуст только при высоких оценках",
    )
    pending: list[PendingFact] = Field(
        default_factory=list,
        description=(
            "Карантин: находки из нереестровых источников со ссылками. В verdict не входят."
        ),
    )
    warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Критические негативные факторы безусловного оповещения (warn_always: true)."
        ),
    )
    unmatched_fact_kinds: list[str] = Field(
        default_factory=list,
        description=(
            "Виды фактов, для которых нет критерия. Непустой список — "
            "сигнал, что пул критериев стоит расширить"
        ),
    )
    profile: dict | None = Field(
        default=None,
        description=(
            "Деловой свод для менеджера (заполняется только при "
            "profile=true в get_verdict): субъект, проверки, судебная "
            "нагрузка, вердикт — те же данные, порядок для чтения"
        ),
    )
    criteria_version: str = Field(
        description=(
            "Хэш scoring.yaml на момент расчёта. Одинаковый YAML — "
            "одинаковый хэш: по нему можно сопоставить две проверки и "
            "узнать, считались ли они по одним правилам. Изменился вес "
            "или добавлен критерий — хэш меняется, и расхождение старого "
            "и нового вердикта перестаёт быть загадкой"
        ),
    )
    scored_at: datetime = Field(description="Когда посчитано")
