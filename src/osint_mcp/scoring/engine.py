"""Движок скоринга.

Читает config_data/scoring.yaml, валидирует и считает оценку по фактам.
Код не знает ни одного конкретного критерия — только операторы, агрегаты
и пороги. Всё «что и насколько важно» — в YAML.
"""

import hashlib
import json
import math
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import BaseModel, Field, ValidationError

from osint_mcp.models import CompanyContext, ExtFact, Fact
from osint_mcp.scoring.models import PendingFact

# Движку всё равно, откуда пришёл факт: у Fact и ExtFact одинаковый
# набор полей, важных для скоринга (kind, fact_id, source_url,
# event_date, payload). Аннотация для читателя, не для валидации.
AnyFact = Fact | ExtFact

from .models import (
    GroupScore,
    MatchedCriterion,
    ScoreResult,
    Verdict,
)

_TABLE_PATH = Path(__file__).parent.parent / "config_data" / "scoring.yaml"

# Зарезервированные имена полей, которые берутся не из payload.
_SPECIAL_FIELDS = {"status": "payload", "link": "payload"}


# ──────────────────────────  Схема конфига  ──────────────────────────

class Threshold(BaseModel):
    above: float | None = None
    below: float | None = None
    score: float
    label: str = Field(default="", description="Подпись ступени для {label} в reason")


class Decay(BaseModel):
    half_life_days: int = Field(gt=0)


class Match(BaseModel):
    kind: str
    field: str | None = None
    op: str = Field(default="exists")
    values: list[Any] = Field(default_factory=list)


class CriterionSpec(BaseModel):
    group: str
    description: str = ""
    match: Match
    aggregate: str = Field(default="count")  # count|sum|max|age_days
    field: str | None = None
    score: float | None = Field(
        default=None,
        description=(
            "Вес критерия в баллах — ставится редактирующим YAML вручную, "
            "код не вычисляет и не нормирует. Отрицательные идут в итог "
            "целиком; положительные масштабируются весом группы"
        ),
    )
    thresholds: list[Threshold] = Field(default_factory=list)
    decay: Decay | None = None
    verdict_floor: str | None = None
    warn_always: bool = Field(
        default=False,
        description=(
            "Тяжёлый фактор: попадает в warnings независимо от итоговой "
            "оценки. Даже если плюсы вытянули вердикт до «надёжный», "
            "этот фактор обязан быть показан пользователю"
        ),
    )
    reason: str = ""


class VerdictSpec(BaseModel):
    min: float | None = None
    max: float | None = None
    label: str
    require_reason: bool = False


class GroupSpec(BaseModel):
    weight: float


class ScoringConfig(BaseModel):
    baseline: float = 60
    groups: dict[str, GroupSpec]
    criteria: dict[str, CriterionSpec]
    verdicts: list[VerdictSpec]
    criteria_version: str = Field(
        default="",
        description=(
            "Заполняется движком при загрузке: хэш содержимого YAML. "
            "В YAML его задавать не нужно — значение из файла игнорируется"
        ),
    )

    def validate_semantics(self) -> None:
        """Ошибки в YAML — это ошибки запуска, а не молчаливая ерунда."""
        for name, c in self.criteria.items():
            if c.group not in self.groups:
                raise ValueError(
                    f"Критерий «{name}» ссылается на несуществующую группу "
                    f"«{c.group}» (есть: {list(self.groups)})"
                )
            if c.score is None and not c.thresholds:
                raise ValueError(
                    f"Критерий «{name}»: нет ни score, ни thresholds"
                )
            if c.aggregate in ("sum", "max") and not c.field:
                raise ValueError(
                    f"Критерий «{name}»: агрегат «{c.aggregate}» требует field"
                )
            if c.verdict_floor and c.verdict_floor not in {
                v.label for v in self.verdicts
            }:
                raise ValueError(
                    f"Критерий «{name}»: verdict_floor «{c.verdict_floor}» "
                    f"не входит в шкалу вердиктов"
                )
        if not self.verdicts:
            raise ValueError("Секция verdicts пуста")


# ──────────────────────────  Загрузка  ──────────────────────────

# Журнал версий правил: какой YAML действовал под каким хэшем.
# Не база данных и не история досье — просто снимок конфига при каждой
# новой версии, чтобы вердикт из прошлого можно было сопоставить с
# правилами, по которым он считался.
_SNAPSHOT_DIR = _TABLE_PATH.parent / "config_snapshots"


def _record_config_snapshot(path: Path, version: str, normalized: str) -> None:
    """Сохранить снимок YAML при появлении новой версии правил.

    Одинаковый контент = одинаковый хэш = запись не дублируется.
    Файл-журнал: config_snapshots/<version>.yaml
    """
    try:
        _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        snap = _SNAPSHOT_DIR / f"{version}.yaml"
        if not snap.exists():
            snap.write_text(normalized, encoding="utf-8")
    except OSError:
        # Журнал — вспомогательная вещь: не смогли записать, работаем
        # дальше без него. Хэш в ScoreResult уже стоит.
        pass


@lru_cache(maxsize=1)
def load_config(path: Path | None = None) -> ScoringConfig:
    p = path or _TABLE_PATH
    with open(p, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    try:
        cfg = ScoringConfig(**raw)
    except ValidationError as e:
        raise ValueError(f"scoring.yaml не соответствует схеме: {e}") from e
    cfg.validate_semantics()
    # Версия правил = хэш от нормализованного содержимого, а не от файла:
    # перенос строк и перестановка ключей не меняют правила.
    normalized = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    cfg.criteria_version = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()[:16]
    _record_config_snapshot(p, cfg.criteria_version, normalized)
    return cfg


def reload_config(path: Path | None = None) -> ScoringConfig:
    """Перечитать YAML (после правки файла без перезапуска)."""
    load_config.cache_clear()
    return load_config(path)


# ──────────────────────────  Операторы  ──────────────────────────

def _get_value(fact: Fact, field: str | None) -> Any:
    """Достать значение: payload.field (с точками для вложенности)."""
    if not field:
        return fact.payload
    value: Any = fact.payload
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _op_contains_any(value: Any, values: list[Any]) -> bool:
    if value is None:
        return False
    text = str(value).lower()
    return any(str(v).lower() in text for v in values)


def _op_eq(value: Any, values: list[Any]) -> bool:
    if value is None:
        return False
    text = str(value).lower()
    return any(text == str(v).lower() for v in values)


def _op_gt(value: Any, values: list[Any]) -> bool:
    return value is not None and float(value) > float(values[0])


def _op_lt(value: Any, values: list[Any]) -> bool:
    return value is not None and float(value) < float(values[0])


def _op_exists(value: Any, _values: list[Any]) -> bool:
    return value is not None and value != ""


_OPERATORS: dict[str, Callable[[Any, list[Any]], bool]] = {
    "contains_any": _op_contains_any,
    "eq": _op_eq,
    "gt": _op_gt,
    "lt": _op_lt,
    "exists": _op_exists,
}


# ──────────────────────────  Затухание  ──────────────────────────

def _decay_factor(fact: Fact, half_life_days: int, today: date) -> float:
    """Свежесть события: полураспад в днях. Факты без даты не затухают."""
    if fact.event_date is None:
        return 1.0
    days = max((today - fact.event_date).days, 0)
    return math.pow(0.5, days / half_life_days)


# ──────────────────────────  Отрисовка причин  ──────────────────────────

def _fmt_num(value: float) -> str:
    if float(value).is_integer():
        return f"{int(value):,}".replace(",", " ")
    return f"{value:,.1f}".replace(",", " ")


def _render_reason(
    template: str, value: float | None, count: int,
    total: float | None, fact: Fact | None,
) -> str:
    out = template
    for placeholder, replacement in (
        ("{value}", _fmt_num(value) if value is not None else "—"),
        ("{sum}", _fmt_num(total) if total is not None else "—"),
        ("{count}", str(count)),
        ("{statement}", fact.statement if fact else "—"),
    ):
        out = out.replace(placeholder, replacement)
    return out


# ──────────────────────────  Основной расчёт  ──────────────────────────

def _pick_threshold_score(
    thresholds: list[Threshold], value: float,
) -> tuple[float, Threshold | None]:
    """Первая подходящая ступень (список идёт от больших порогов вниз)."""
    for t in thresholds:
        if t.above is not None and value > t.above:
            return t.score, t
        if t.below is not None and value < t.below:
            return t.score, t
    return 0.0, None


def _score_criterion(
    name: str, spec: CriterionSpec,
    facts: list[AnyFact], context: CompanyContext | None,
    group_weight: float, today: date,
) -> MatchedCriterion | None:
    # age_days считается от даты регистрации в контексте — факты не нужны.
    if spec.aggregate == "age_days":
        if context is None or context.registered_at is None:
            return None
        raw_value = float((today - context.registered_at).days)
        base_score, _ = _pick_threshold_score(spec.thresholds, raw_value)
        if base_score == 0.0 and spec.score is None:
            # Порог не сработал: возраст в «серой зоне» (1–5 лет) — нейтрально.
            return None
        if spec.reason:
            _, hit = _pick_threshold_score(spec.thresholds, raw_value)
            threshold_label = getattr(hit, "label", None) or ""
            reason = spec.reason.replace("{label}", threshold_label)
        else:
            reason = ""
        return MatchedCriterion(
            criterion=name, group=spec.group,
            description=spec.description,
            score=round(base_score, 1),
            raw_value=raw_value,
            fact_ids=[], source_urls=(
                [f"https://checko.ru/company/{context.inn}"]
                if context.inn else []
            ),
            reason=reason,
        )

    op = _OPERATORS.get(spec.match.op)
    if op is None:
        raise ValueError(
            f"Критерий «{name}»: неизвестный оператор «{spec.match.op}» "
            f"(доступны: {sorted(_OPERATORS)})"
        )
    matched = []
    for f in facts:
        if f.kind != spec.match.kind:
            continue
        value = _get_value(f, spec.match.field)
        if op(value, spec.match.values):
            matched.append(f)
    if not matched:
        return None

    # 2. Агрегация (+затухание по event_date, если задано).
    if spec.aggregate == "age_days":
        if context is None or context.registered_at is None:
            return None
        raw_value = float((today - context.registered_at).days)
    elif spec.aggregate == "count":
        raw_value = float(len(matched))
    else:  # sum / max
        values = [float(_get_value(f, spec.field) or 0.0) for f in matched]
        raw_value = sum(values) if spec.aggregate == "sum" else max(values)

    # 3. Балл: фиксированный или по ступеням; затухание — множителем.
    if spec.score is not None:
        base_score = spec.score
    else:
        base_score, _ = _pick_threshold_score(spec.thresholds, raw_value)
    if spec.decay is not None:
        # Множитель по «свежайшему» событию: старые пачки долгов не должны
        # тянуть так же, как вчерашние. Для sum считаем средний множитель.
        factors = [_decay_factor(f, spec.decay.half_life_days, today)
                   for f in matched]
        decay_mult = sum(factors) / len(factors)
    else:
        decay_mult = 1.0
    score = base_score * decay_mult

    # 4. Вес группы: нейтральные группы не размывают жёсткие полы,
    # поэтому вклад группы нормируется на её долю в 100 только для
    # положительных баллов; отрицательные идут целиком.
    if score < 0:
        weighted = score
    else:
        weighted = score * (group_weight / 100.0)

    fact_ids = [f.fact_id for f in matched]
    source_urls = sorted({f.source_url for f in matched})
    if spec.reason:
        # {label} подставляется из сработавшей ступени порога.
        if "{label}" in spec.reason and spec.thresholds:
            _, hit = _pick_threshold_score(spec.thresholds, raw_value)
            label = getattr(hit, "label", None) or ""
            reason = spec.reason.replace("{label}", label)
        else:
            reason = _render_reason(
                spec.reason, raw_value, len(matched),
                raw_value if spec.aggregate == "sum" else None,
                matched[0],
            )
    else:
        reason = ""
    return MatchedCriterion(
        criterion=name, group=spec.group,
        description=spec.description,
        score=round(weighted, 1),
        raw_value=raw_value if spec.aggregate != "count" else len(matched),
        fact_ids=fact_ids, source_urls=source_urls, reason=reason,
    )


def _pick_verdict(
    total: float, cfg: ScoringConfig, floors: list[tuple[str, str]],
) -> Verdict:
    label = cfg.verdicts[0].label
    floored = False
    floor_by: str | None = None
    for v in cfg.verdicts:
        if v.min is not None and total >= v.min:
            label = v.label
            break
        if v.max is not None and total <= v.max:
            label = v.label
            break
    else:
        label = cfg.verdicts[-1].label

    # Жёсткий пол: применяем самый строгий из сработавших.
    # verdicts упорядочены от лучшего к худшему, поэтому «строже» = больший индекс.
    floor_order = {v.label: i for i, v in enumerate(cfg.verdicts)}
    for crit_name, floor in floors:
        if floor_order.get(floor, -1) > floor_order.get(label, -1):
            label = floor
            floored = True
            floor_by = crit_name
    return Verdict(label=label, total_score=round(total, 1),
                   floored=floored, floor_criterion=floor_by)


def score_company(
    facts: list[AnyFact],
    context: CompanyContext | None = None,
    config_path: Path | None = None,
    pending: list[PendingFact] | None = None,
) -> ScoreResult:
    cfg = load_config(config_path)
    today = date.today()
    now = datetime.now(timezone.utc)

    # Группа -> вес, нормированный на 100.
    total_weight = sum(g.weight for g in cfg.groups.values()) or 1.0
    weights = {name: g.weight / total_weight * 100
               for name, g in cfg.groups.items()}

    matched: list[MatchedCriterion] = []
    floors: list[tuple[str, str]] = []
    used_kinds: set[str] = set()

    for name, spec in cfg.criteria.items():
        # age_days опирается на context.registered_at, факты не матчит.
        candidates = facts if spec.aggregate != "age_days" else facts
        result = _score_criterion(
            name, spec, candidates, context, weights.get(spec.group, 0), today,
        )
        if result is None:
            continue
        matched.append(result)
        used_kinds.add(spec.match.kind)
        if spec.verdict_floor:
            floors.append((name, spec.verdict_floor))

    # Виды фактов без критериев — сигнал расширять пул.
    unmatched = sorted({f.kind for f in facts} - used_kinds)

    # Вклад групп.
    group_scores: list[GroupScore] = []
    total = cfg.baseline
    for gname, weight in weights.items():
        gscore = sum(m.score for m in matched if m.group == gname)
        # Отрицательные баллы уже не ослаблены весом; в разрезе групп
        # показываем как есть, чтобы пользователь видел вклад честно.
        weighted = gscore
        group_scores.append(GroupScore(
            group=gname, weight=round(weight, 1),
            score=round(gscore, 1), weighted=round(weighted, 1),
        ))
    total += sum(m.score for m in matched)

    verdict = _pick_verdict(total, cfg, floors)

    reasons = [
        m.reason for m in matched
        if m.reason and m.score < 0
    ]
    positive = [m.reason for m in matched if m.reason and m.score > 0]
    require_reason = any(
        v.require_reason and v.label == verdict.label for v in cfg.verdicts
    )
    if require_reason and not reasons:
        # Не должны остаться без объяснения: добавляем позитивный контекст.
        reasons = positive or [
            "Итог сформирован базовыми сведениями реестра без существенных "
            "риск-факторов"
        ]

    # Тяжёлые факторы — отдельно: они всплывают даже при хорошей оценке.
    # Порядок: самые крупные минусы первыми.
    warnings = [
        m.reason or m.description
        for m in sorted(matched, key=lambda m: m.score)
        if m.score < 0 and cfg.criteria[m.criterion].warn_always
    ]

    return ScoreResult(
        inn=context.inn if context else "",
        verdict=verdict,
        groups=group_scores,
        matched=matched,
        reasons=reasons,
        pending=pending or [],
        warnings=warnings,
        unmatched_fact_kinds=unmatched,
        criteria_version=cfg.criteria_version,
        scored_at=now,
    )
