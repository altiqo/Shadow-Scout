"""Общие хелперы для экспортёров: строки таблицы, подписи."""

from __future__ import annotations

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
    ("flags", "Флаги"),
]


def yes_no(value: bool | None) -> str:
    if value is None:
        return "?"
    return "да" if value else "нет"


def fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def row_for(rank: int, report: RiskReport, lang: str = "ru") -> dict[str, str]:
    countries = load_countries()
    p = report.provider
    locs = report.matched_locations or p.locations
    loc_text = ", ".join(sorted({f"{countries.name(loc.country, lang)}" + (f" ({loc.city})" if loc.city else "") for loc in locs}))
    holders = "; ".join(f"AS{a.asn}: {a.holder or '?'}" for a in report.asns)
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
        "trial": yes_no(p.trial),
        "hourly": yes_no(p.hourly),
        "price": f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—",
        "survivability": f"{report.survivability:.0f}",
        "risk": f"{report.risk_score:.0f}",
        "verdict": VERDICT_LABELS_RU.get(report.verdict, report.verdict),
        "confidence": f"{report.confidence * 100:.0f}%",
        "flags": "; ".join(report.hard_flags),
    }


def rows_for(result: SearchResult, lang: str = "ru") -> list[dict[str, str]]:
    return [row_for(i, r, lang) for i, r in enumerate(result.sorted_reports(), start=1)]


def summary_counts(result: SearchResult) -> dict[str, int]:
    counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0, "unknown": 0}
    for r in result.reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts
