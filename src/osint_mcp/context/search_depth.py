"""Search work limits for each dossier detail level."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SearchDepth:
    reputation_platforms: tuple[str, ...]
    media_queries: int | None
    competitor_discovery: int
    competitor_news: int


_DEPTHS = {
    "brief": SearchDepth(("federal_media", "cyber_leaks"), 1, 0, 0),
    "standard": SearchDepth(("federal_media", "cyber_leaks", "disasters", "blacklists"), 4, 1, 2),
    "full": SearchDepth(("disasters", "cyber_leaks", "federal_media", "vc_ru", "habr", "blacklists"), None, 2, 5),
}


def search_depth(detail: str) -> SearchDepth:
    value = str(detail or "").strip().lower()
    level = {
        "кратко": "brief", "коротко": "brief", "short": "brief", "1": "brief",
        "средне": "standard", "medium": "standard", "стандарт": "standard", "обычно": "standard", "2": "standard",
        "полно": "full", "детально": "full", "detailed": "full", "максимум": "full",
        "deep": "full", "максимально": "full", "3": "full",
    }.get(value, value)
    return _DEPTHS.get(level, _DEPTHS["standard"])
