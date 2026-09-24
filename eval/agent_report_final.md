# Финальный прогон агента opencode (все исправления)

Модель: opencode/nemotron-3.5-lightning-free, ИНН 7724744134.

## Инструмент: osint-mcp_resolve_company — completed
```
input: {"query": "7724744134"}
output(первые 2500 симв.): {
  "query": "7724744134",
  "status": "unavailable",
  "reason": "Не задан ключ DADATA: заполните DADATA_API_KEY или DADATA_API_KEYS в .env.",
  "confidence": "none",
  "total_found": 0,
  "candidates": [],
  "hint": "Источник недоступен. Это НЕ означает, что компания не найдена."
}
```
## Инструмент: osint-mcp_get_company_context — completed
```
input: {"inn": "7724744134"}
output(первые 2500 симв.): {
  "status": "ok",
  "reason": "Базовая карточка собрана напрямую из сервиса ЕГРЮЛ: DaData недоступна (Не задан ключ DADATA: заполните DADATA_API_KEY или DADATA_API_KEYS в .env.), Checko недоступен (Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.). Данных в карточке минимум — масштаб, финансы и связи НЕ ПРОВЕРЕНЫ. Масштаб организации НЕ УСТАНОВЛЕН: Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.. Поля size_category, employees, revenue_latest и capital пусты ПОТОМУ ЧТО проверка не состоялась, а не потому что сведений нет. Не делай выводов о размере компании. Финансовая история собрана из ГИР БО (бесплатный ресурс ФНС): выручка и активы по годам есть, прибыль и численность НЕ УСТАНОВЛЕНЫ (Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.). Прежние наименования НЕ ПРОВЕРЕНЫ: ошибка источника (QuotaExhausted). Пустой former_names здесь НЕ означает, что организация не переименовывалась. Организация ИСКЛЮЧЕНА из реестра МСП 2024-07-10 — её категория в реестре устарела и не использована. Масштаб оценивай по выручке и численности из финансовой истории, а не по size_category. Рыночное наименование не установлено. Веб-поиск будет вестись только по юридическому наименованию, и отсутствие негативных находок НИЧЕГО НЕ ДОКАЖЕТ — обязательно оговори это в выводах.",
  "context": {
    "inn": "7724744134",
    "country": "RU",
    "ogrn": "1107746293049",
    "name_legal": "ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"БПМСОФТ\"",
    "name_short": "ООО \"БПМСОФТ\"",
    "status": null,
    "registered_at": "2010-04-15",
    "address_full": null,
    "city": null,
    "region": "Г.Москва",
    "director_fio": "Востриков Юрий Викторович",
    "director_post": "ГЕНЕРАЛЬНЫЙ ДИРЕКТОР",
    "founders": [],
    "okved_code": null,
    "okved_text": null,
    "capital": null,
    "name_variants": [],
    "industry_terms": [],
    "brand_resolved": false,
    "brand": null,
    "former_names": [],
    "brand_domain": null,
    "brand_summary": null,
    "size_category": "unknown",
    "employees": 386,
    "branches": null,
    "representative_offices": null,
    "revenue_latest": 2769645000.0,
    "fin_history": [
      {
        "year": 2025,
        "revenue": 2769645000.0,
        "profit": null,
        "assets": 2113081000.0,
        "balance": null,
        "equity": null,
        "report_url": "https://bo.nalog.gov.ru/bfo/pdf
```
## Инструмент: osint-mcp_check_affiliations — completed
```
input: {"inn": "7724744134", "deep": true}
output(первые 2500 симв.): {
  "inn": "7724744134",
  "people": [],
  "owner_organizations": [],
  "predecessors": [],
  "successors": [],
  "related_companies": [],
  "suspicious_count": 0,
  "shareholders_undisclosed": false,
  "coverage_note": "Проверка связей НЕ ВЫПОЛНЕНА: Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.. Пустые списки здесь не означают отсутствия связей."
}
```
## Инструмент: osint-mcp_get_verdict — completed
```
input: {"inn": "7724744134"}
output(первые 2500 симв.): {
  "inn": "7724744134",
  "verdict": {
    "label": "нельзя",
    "total_score": 0.0,
    "floored": false,
    "floor_criterion": null
  },
  "groups": [],
  "matched": [],
  "reasons": [
    "Оценка не производилась — Реестровые источники недоступны: Базовая карточка собрана напрямую из сервиса ЕГРЮЛ: DaData недоступна (Не задан ключ DADATA: заполните DADATA_API_KEY или DADATA_API_KEYS в .env.), Checko недоступен (Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.). Данных в карточке минимум — масштаб, финансы и связи НЕ ПРОВЕРЕНЫ. Масштаб организации НЕ УСТАНОВЛЕН: Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.. Поля size_category, employees, revenue_latest и capital пусты ПОТОМУ ЧТО проверка не состоялась, а не потому что сведений нет. Не делай выводов о размере компании. Финансовая история собрана из ГИР БО (бесплатный ресурс ФНС): выручка и активы по годам есть, прибыль и численность НЕ УСТАНОВЛЕНЫ (Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env.). Прежние наименования НЕ ПРОВЕРЕНЫ: ошибка источника (QuotaExhausted). Пустой former_names здесь НЕ означает, что организация не переименовывалась. Организация ИСКЛЮЧЕНА из реестра МСП 2024-07-10 — её категория в реестре устарела и не использована. Масштаб оценивай по выручке и численности из финансовой истории, а не по size_category. Рыночное наименование не установлено. Веб-поиск будет вестись только по юридическому наименованию, и отсутствие негативных находок НИЧЕГО НЕ ДОКАЖЕТ — обязательно оговори это в выводах.. Оценка НЕ ВЫСТАВЛЕНА: ни один источник рисков не ответил, выдавать вердикт по непроверенной организации нельзя. Карточка компании сама по себе проверкой рисков не является. Проверьте ключи DaData/Checko в .env и доступность API."
  ],
  "pending": [],
  "warnings": [
    "Оценка НЕ ВЫСТАВЛЕНА: источники недоступны, организацию никто не проверял. НЕ РАБОТАЙТЕ с этим вердиктом как с реальной оценкой."
  ],
  "unmatched_fact_kinds": [],
  "profile": null,
  "criteria_version": "343ead90c7e1e3be",
  "scored_at": "2026-09-24T08:13:21.807116Z"
}
```
## Финальный ответ агента (дословно)
**ЧТО ПОЛУЧИЛОСЬ**  
- **get_company_context**: ООО «БПМСОФТ» зарегистрировано 15 апреля 2010 г. в г.Москва, генеральный директор — Востриков Ю. В.; выручка за 2025 год — 2 769 645 000 руб.

**ЧТО НЕ РАБОТАЕТ**  
- **resolve_company**: статус unavailable, причина дословно — «Не задан ключ DADATA: заполните DADATA_API_KEY или DADATA_API_KEYS в .env.».  
- **check_affiliations**: coverage_note дословно — «Проверка связей НЕ ВЫПОЛНЕНА: Ключи Checko исчерпаны: Не задан ключ CHECKO: заполните CHECKO_API_KEY или CHECKO_API_KEYS в .env..». (Владельцы‑организации, в т. ч. АО «ЛАНСОФТ», из deep_summary не выявлены).

**ИТОГ**  
Вердикт get_verdict: **«нельзя»** (общий балл 0.0), так как реестровые источники рисков недоступны, проверить компанию невозможно.