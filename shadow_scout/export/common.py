"""Общие хелперы для экспортёров: строки таблицы, подписи."""

from __future__ import annotations

from collections import defaultdict

from shadow_scout.models import VERDICT_LABELS_RU, RiskReport, SearchResult
from shadow_scout.providers import load_countries

COLUMNS = [
    ("rank", "#"),
    ("provider", "Провайдер"),
    ("website", "Сайт"),
    ("countries", "Страны/локации"),
    ("asns", "ASN"),
    ("holder", "Holder (RIPE)"),
    ("ipv4", "IPv4 всего"),
    ("blocked_share", "В списках, %"),
    ("ip_type", "Тип IP"),
    ("trial", "Trial"),
    ("hourly", "Почасовая"),
    ("price", "Цена от, €"),
    ("survivability", "Выживаемость"),
    ("risk", "Риск"),
    ("verdict", "Вердикт"),
    ("confidence", "Уверенность"),
    ("depth", "Проверка"),
    ("picks", "Лучший в локациях"),
    ("source", "Источник данных"),
    ("flags", "Флаги"),
]

PICK_COLUMNS = [
    ("location", "Локация"),
    ("rank", "#"),
    ("provider", "Провайдер"),
    ("cities", "Города"),
    ("asns", "ASN"),
    ("ipv4", "IPv4 всего"),
    ("blocked_share", "В списках, %"),
    ("trial", "Trial"),
    ("hourly", "Почасовая"),
    ("price", "Цена от, €"),
    ("survivability", "Выживаемость"),
    ("verdict", "Вердикт"),
    ("depth", "Проверка"),
    ("website", "Сайт"),
]

DEPTH_LABELS = {"full": "полная", "quick": "быстрая"}
SOURCE_LABELS = {"bundled": "ручная база", "catalog": "автокаталог", "user": "пользовательская", "discovered": "discovery", "adhoc": "разовая проверка"}


def location_title(country: str, city: str | None = None, lang: str = "ru") -> str:
    name = load_countries().name(country, lang)
    return f"{name} ({country})" + (f" · {city}" if city else "")


def pick_labels(result: SearchResult) -> dict[str, list[str]]:
    """provider_id → в каких локациях и на каком месте он «лучший», например «SE #1»."""
    labels: dict[str, list[str]] = defaultdict(list)
    for pick in result.picks:
        for rank, pid in enumerate(pick.provider_ids, start=1):
            labels[pid].append(f"{pick.key} #{rank}")
    return labels


def picked_reports(result: SearchResult) -> list[RiskReport]:
    """Провайдеры, попавшие в «лучшие» хотя бы одной локации, — без повторов, в порядке появления."""
    seen: dict[str, RiskReport] = {}
    for pick in result.picks:
        for pid in pick.provider_ids:
            report = result.report_by_id(pid)
            if report is not None and pid not in seen:
                seen[pid] = report
    return list(seen.values())


def pick_rows(result: SearchResult, lang: str = "ru") -> list[dict[str, str]]:
    """Плоские строки «локация → место → провайдер» для таблиц экспорта."""
    rows: list[dict[str, str]] = []
    for pick in result.picks:
        for rank, pid in enumerate(pick.provider_ids, start=1):
            report = result.report_by_id(pid)
            if report is None:
                continue
            p = report.provider
            cities = ", ".join(sorted({loc.city for loc in p.locations if loc.country == pick.country and loc.city}))
            rows.append({
                "location": location_title(pick.country, pick.city, lang),
                "rank": str(rank),
                "provider": p.name,
                "cities": cities or "—",
                "asns": ", ".join(f"AS{a.asn}" for a in report.asns) or "—",
                "ipv4": fmt_int(report.total_ipv4) if report.total_ipv4 else "—",
                "blocked_share": f"{report.blocked_share * 100:.2f}" if report.total_ipv4 else "—",
                "trial": yes_no(p.trial, p.hints_only),
                "hourly": yes_no(p.hourly, p.hints_only),
                "price": f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—",
                "survivability": f"{report.survivability:.0f}",
                "verdict": VERDICT_LABELS_RU.get(report.verdict, report.verdict),
                "depth": DEPTH_LABELS.get(report.depth, report.depth),
                "website": p.website or "",
            })
    return rows


def holder_label(report: RiskReport, holder: str | None) -> str:
    """Держатель ASN: у быстрой проверки его не запрашивали — это не то же самое, что «неизвестно»."""
    if holder:
        return holder
    return "не запрашивался (быстрая проверка)" if report.depth == "quick" else "?"


def yes_no(value: bool | None, hint: bool = False) -> str:
    """да / нет / ? (неизвестно); «да (авто)» — определено автоматически и не проверялось вручную."""
    if value is None:
        return "?"
    if not value:
        return "нет"
    return "да (авто)" if hint else "да"


def fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def row_for(rank: int, report: RiskReport, lang: str = "ru", labels: dict[str, list[str]] | None = None) -> dict[str, str]:
    countries = load_countries()
    p = report.provider
    locs = report.matched_locations or p.locations
    loc_text = ", ".join(sorted({f"{countries.name(loc.country, lang)}" + (f" ({loc.city})" if loc.city else "") for loc in locs}))
    holders = "; ".join(f"AS{a.asn}: {holder_label(report, a.holder)}" for a in report.asns)
    return {
        "rank": str(rank),
        "provider": p.name,
        "website": p.website or "",
        "countries": loc_text,
        "asns": ", ".join(f"AS{a.asn}" for a in report.asns) or ", ".join(f"AS{a}" for a in p.asns) or "—",
        "holder": holders,
        "ipv4": fmt_int(report.total_ipv4) if report.total_ipv4 else "—",
        "blocked_share": f"{report.blocked_share * 100:.2f}" if report.total_ipv4 else "—",
        "ip_type": p.ip_type.upper(),
        "trial": yes_no(p.trial, p.hints_only),
        "hourly": yes_no(p.hourly, p.hints_only),
        "price": f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—",
        "survivability": f"{report.survivability:.0f}",
        "risk": f"{report.risk_score:.0f}",
        "verdict": VERDICT_LABELS_RU.get(report.verdict, report.verdict),
        "confidence": f"{report.confidence * 100:.0f}%",
        "depth": DEPTH_LABELS.get(report.depth, report.depth),
        "picks": ", ".join((labels or {}).get(p.id, [])),
        "source": SOURCE_LABELS.get(p.source, p.source),
        "flags": "; ".join(report.hard_flags),
    }


def rows_for(result: SearchResult, lang: str = "ru") -> list[dict[str, str]]:
    labels = pick_labels(result)
    return [row_for(i, r, lang, labels) for i, r in enumerate(result.sorted_reports(), start=1)]


def summary_counts(result: SearchResult) -> dict[str, int]:
    counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0, "unknown": 0}
    for r in result.reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts
