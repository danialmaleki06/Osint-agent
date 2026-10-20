from osint_mcp.models import CompanyContext, HiringInfo
from osint_mcp.tools.statutory_hr import build_statutory_hr_profile


def test_build_statutory_hr_profile_bpmsoft():
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"',
        employees=386,
        revenue_latest=2_769_645_000.0,
        hiring=HiringInfo(open_vacancies=15),
    )
    res = build_statutory_hr_profile(ctx)
    assert res is not None
    assert res["официальный_штат_фнс"] == 386
    assert res["открыто_вакансий_30дней"] == 15
    assert res["доля_найма_к_штату_процент"] == 3.89
    assert res["динамика_найма"] == "плановая_ротация"
    assert res["выручка_на_сотрудника_руб"] == round(2_769_645_000 / 386)


def test_build_statutory_hr_profile_high_hiring():
    ctx = CompanyContext(
        inn="1234567890",
        name_legal="ООО Стартап",
        employees=50,
        hiring=HiringInfo(open_vacancies=20),
    )
    res = build_statutory_hr_profile(ctx)
    assert res is not None
    assert res["динамика_найма"] == "аномальный_найм"
    assert res["доля_найма_к_штату_процент"] == 40.0


def test_build_statutory_hr_profile_none():
    assert build_statutory_hr_profile(None) is None
    ctx = CompanyContext(inn="123", name_legal="ООО Пусто")
    assert build_statutory_hr_profile(ctx) is None
