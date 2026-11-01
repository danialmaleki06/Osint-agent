"""Скрипт сквозного аудита стабильности всех источников данных osint-mcp.
Проверяет живые вызовы ко всем поддерживаемым реестрам, API и OSINT-модулям:
1. DaData API
2. Checko API (ротация ключей, квоты)
3. Бесплатный официальный эшелон:
   - ГИР БО (bo.nalog.gov.ru)
   - Реестр МСП (rmsp.nalog.ru)
   - Сервис ЕГРЮЛ (egrul.nalog.ru)
   - Федресурс (fedresurs.ru)
   - HeadHunter API (dev.hh.ru)
4. OSINT-модули:
   - Анализ сайта, SSL, WHOIS и веб-аналитика (site.py)
   - Таможня и ВЭД (customs.py)
   - Гео-отзывы и панорамы (geo_reviews.py)
   - Репутационные инциденты и СМИ (reputation_fiascos.py)
"""

import asyncio
import time

from osint_mcp.context.bo_nalog import BoNalogSource
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.customs import build_customs_facts
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.context.egrul import EgrulSource
from osint_mcp.context.fedresurs import FedresursSource
from osint_mcp.context.geo_reviews import build_geo_reviews_facts
from osint_mcp.context.hh import HhSource
from osint_mcp.context.reputation_fiascos import async_build_reputation_fiasco_facts
from osint_mcp.context.rmsp import RmspSource
from osint_mcp.context.site import inspect_site_content

TEST_INN = "7724744134"  # ООО БПМСофт
TEST_COMPANY = "ООО БПМСофт"
TEST_DOMAIN = "bpmsoft.ru"
TEST_ADDRESS = "г. Москва, Варшавское шоссе, д. 118, к. 1"


async def test_dadata():
    print("\n--- 1. Testing DaData ---")
    s = DaDataSource()
    t0 = time.time()
    try:
        res = await s.resolve(TEST_INN)
        print(f"DaData resolve: status={res.status}, conf={res.confidence}, total={res.total_found}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"DaData resolve FAILED: {type(e).__name__}: {e}")

    t0 = time.time()
    try:
        ctx_res = await s.get_context(TEST_INN)
        ctx = ctx_res.context
        print(f"DaData context: status={ctx_res.status}, name={ctx.name_legal if ctx else None}, ogrn={ctx.ogrn if ctx else None}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"DaData get_context FAILED: {type(e).__name__}: {e}")


async def test_checko():
    print("\n--- 2. Testing Checko ---")
    s = CheckoSource()
    t0 = time.time()
    try:
        ctx_res = await s.get_context(TEST_INN)
        ctx = ctx_res.context
        print(f"Checko context: status={ctx_res.status}, name={ctx.name_legal if ctx else None}, reason={ctx_res.reason}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Checko context FAILED: {type(e).__name__}: {e}")

    t0 = time.time()
    try:
        fin_summary, fin_failure = await s.get_finances(TEST_INN)
        years = fin_summary.years if fin_summary else []
        print(f"Checko finances: years={len(years)}, reason={fin_failure}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Checko finances FAILED: {type(e).__name__}: {e}")

    t0 = time.time()
    try:
        graph, res = await s.check_affiliations(TEST_INN, deep=False)
        people_cnt = len(graph.people) if graph else 0
        rel_cnt = len(graph.related_companies) if graph else 0
        print(f"Checko affiliations: status={res.status}, people={people_cnt}, related={rel_cnt}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Checko affiliations FAILED: {type(e).__name__}: {e}")


async def test_free_tier():
    print("\n--- 3. Testing Free Official Registries (No Key Required) ---")

    # 3.1 GBO (bo.nalog.gov.ru)
    t0 = time.time()
    try:
        bo = BoNalogSource()
        years, failure = await bo.get_finances(TEST_INN)
        print(f"ГИР БО (ФНС): years={len(years) if years else 0}, failure={failure}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"ГИР БО FAILED: {type(e).__name__}: {e}")

    # 3.2 RMSP (rmsp.nalog.ru)
    t0 = time.time()
    try:
        rmsp = RmspSource()
        msp, failure = await rmsp.get_msp(TEST_INN)
        print(f"Реестр МСП (ФНС): in_registry={msp.in_registry if msp else False}, category={msp.category if msp else None}, failure={failure}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Реестр МСП FAILED: {type(e).__name__}: {e}")

    # 3.3 EGRUL (egrul.nalog.ru)
    t0 = time.time()
    try:
        egrul = EgrulSource()
        card, failure = await egrul.get_card(TEST_INN)
        print(f"ЕГРЮЛ (ФНС): found={card is not None}, name={card.get('c') if card else None}, failure={failure}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"ЕГРЮЛ FAILED: {type(e).__name__}: {e}")

    # 3.4 Fedresurs (fedresurs.ru)
    t0 = time.time()
    try:
        fed = FedresursSource()
        res = await fed.check_commercial_facts(TEST_INN)
        print(f"Федресурс: status={res.status}, facts={len(res.facts)}, reason={res.reason[:40] if res.reason else None}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Федресурс FAILED: {type(e).__name__}: {e}")

    # 3.5 HH API (hh.ru)
    t0 = time.time()
    try:
        hh = HhSource()
        hiring = await hh.get_hiring("БПМСОФТ", TEST_INN)
        print(f"HeadHunter: vacancies={hiring.open_vacancies}, it_investing={hiring.it_investing}, reason={hiring.reason}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"HeadHunter FAILED: {type(e).__name__}: {e}")


async def test_osint_modules():
    print("\n--- 4. Testing OSINT Modules ---")

    # 4.1 Site & trackers
    t0 = time.time()
    try:
        h1, tech, err = await inspect_site_content(TEST_DOMAIN)
        trackers = tech.tracker_ids if tech else {}
        print(f"Site inspection ({TEST_DOMAIN}): h1={h1[:30] if h1 else None}, trackers={list(trackers.keys())}, err={err}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Site inspection FAILED: {type(e).__name__}: {e}")

    # 4.2 Customs / VED
    t0 = time.time()
    try:
        customs_facts = await asyncio.to_thread(build_customs_facts, TEST_INN, company_name=TEST_COMPANY)
        print(f"Customs / VED: facts={len(customs_facts)}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Customs FAILED: {type(e).__name__}: {e}")

    # 4.3 Geo reviews
    t0 = time.time()
    try:
        geo_facts = await asyncio.to_thread(build_geo_reviews_facts, TEST_INN, company_name=TEST_COMPANY, address=TEST_ADDRESS)
        print(f"Geo reviews: facts={len(geo_facts)}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Geo reviews FAILED: {type(e).__name__}: {e}")

    # 4.4 Reputation fiascos
    t0 = time.time()
    try:
        fiasco_facts = await async_build_reputation_fiasco_facts(TEST_INN, TEST_COMPANY, brand="BPMSoft")
        print(f"Reputation fiascos: facts={len(fiasco_facts)}, time={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"Reputation fiascos FAILED: {type(e).__name__}: {e}")


async def main():
    print(f"============================================================")
    print(f"OSINT-MCP FULL SOURCE AUDIT FOR INN: {TEST_INN}")
    print(f"============================================================")
    await test_dadata()
    await test_checko()
    await test_free_tier()
    await test_osint_modules()
    print("\n============================================================")
    print("AUDIT COMPLETED")
    print("============================================================")


if __name__ == "__main__":
    asyncio.run(main())
