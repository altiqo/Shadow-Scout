"""Проверка самой базы провайдеров против живых данных: ASN, держатель, размер сети, сайт, заявленные условия.

База растёт на сотни записей и устаревает: ASN переезжают, сайты умирают, хостеры вводят или отменяют почасовую
оплату. Эта проверка находит такие расхождения, пока их не нашёл пользователь на этапе оплаты.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Literal

import httpx
from pydantic import BaseModel

from shadow_scout.analysis.engine import AnalysisEngine, Services, holder_matches
from shadow_scout.cache import DiskCache
from shadow_scout.harvest.classify import ru_linked, size_class
from shadow_scout.harvest.webscan import WebScan, scan_many
from shadow_scout.models import SIZE_ORDER, Provider
from shadow_scout.net.http import HttpError
from shadow_scout.net.ipindex import ipv4_size
from shadow_scout.providers import load_countries

Level = Literal["error", "warn", "info"]


class DbIssue(BaseModel):
    provider_id: str
    name: str
    level: Level
    code: str
    message: str


def _issue(p: Provider, level: Level, code: str, message: str) -> DbIssue:
    return DbIssue(provider_id=p.id, name=p.name, level=level, code=code, message=message)


async def check_provider(services: Services, provider: Provider, scan: WebScan | None = None) -> list[DbIssue]:
    """Сверяет запись с RIPEstat/ipverse и (если передан) результатом проверки сайта."""
    out: list[DbIssue] = []
    engine = AnalysisEngine(services)
    countries = load_countries()

    # ── ASN ──
    asns, how = await engine.resolve_asns(provider)
    if not provider.asns and not provider.asn_search:
        out.append(_issue(provider, "error", "no-asn", "не указан ни ASN, ни строка поиска"))
    elif not asns:
        out.append(_issue(provider, "error", "asn-unresolved", f"ASN не найден по запросу «{provider.asn_search or provider.name}»"))
    elif not provider.asns:
        out.append(_issue(provider, "warn", "asn-by-search", "ASN определяется поиском по названию — зафиксируйте явно: asns: " + str(asns)))

    total_ipv4 = 0
    for asn in asns:
        try:
            overview = await services.ripe.as_overview(asn)
        except HttpError as exc:
            out.append(_issue(provider, "info", "ripestat-unavailable", f"AS{asn}: RIPEstat недоступен ({exc})"))
            continue
        if overview.get("announced") is False:
            out.append(_issue(provider, "error", "asn-not-announced", f"AS{asn} сейчас не анонсируется в BGP"))
        match = holder_matches(provider, overview.get("holder"))
        if match is False:
            out.append(_issue(provider, "warn", "holder-mismatch", f"AS{asn}: держатель «{overview.get('holder')}» не похож на «{provider.name}»"))
        prefixes, _src = await services.prefixes.prefixes(asn, prefer="ipverse")
        total_ipv4 += sum(ipv4_size(p) for p in prefixes if ":" not in p)

    # ── размер: заявленный класс против фактического ──
    if total_ipv4:
        real = size_class(total_ipv4)
        if abs(SIZE_ORDER[real] - SIZE_ORDER[provider.size]) >= 2:
            out.append(_issue(provider, "warn", "size-mismatch", f"в записи размер «{provider.size}», по префиксам — «{real}» ({total_ipv4:,} IPv4)".replace(",", " ")))
    elif asns:
        out.append(_issue(provider, "warn", "no-prefixes", "у ASN нет IPv4-префиксов"))

    # ── страны ──
    for code in {provider.hq_country, *(loc.country for loc in provider.locations)} - {"ZZ"}:
        if code not in countries.countries:
            out.append(_issue(provider, "info", "unknown-country", f"страны {code} нет в таблице стран — не появится в мастере"))

    # ── сайт ──
    if scan is not None:
        if not provider.website:
            out.append(_issue(provider, "info", "no-website", "не указан сайт"))
        elif not scan.fetched:
            out.append(_issue(provider, "warn", "site-unreachable", f"сайт {provider.website} не открылся ({scan.error or 'нет ответа'})"))
        else:
            if provider.vps is True and not scan.vps and provider.source != "catalog":
                out.append(_issue(provider, "info", "no-vps-evidence", "на сайте не найдено упоминаний VPS/облачных серверов (возможно, другой язык или вложенная страница)"))
            if scan.hourly and provider.hourly is False:
                out.append(_issue(provider, "warn", "hourly-conflict", "в записи почасовой оплаты нет, а сайт её упоминает — проверьте тарифы: «…" + scan.hourly_evidence + "…»"))
            if provider.hourly is True and scan.vps and not scan.hourly:
                out.append(_issue(provider, "info", "hourly-unconfirmed", "в записи почасовая оплата есть, но на сайте она не найдена"))
            if (scan.russian or ru_linked(provider.name, provider.website)) and not provider.ru_ties:
                out.append(_issue(provider, "warn", "ru-ties-missing", "сайт на русском / российский домен или бренд, а ru_ties не выставлен"))
    return out


async def check_database(
    services: Services,
    providers: list[Provider],
    *,
    web: bool = True,
    concurrency: int = 8,
    progress: Callable[[int, int], None] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    web_cache: DiskCache | None = None,
) -> list[DbIssue]:
    scans: dict[str, WebScan] = {}
    if web:
        sites = {p.id: p.website for p in providers if p.website}
        scans = await scan_many(
            sites, concurrency=24, proxy=services.settings.network.proxy, user_agent=services.settings.network.user_agent,
            cache=web_cache or DiskCache("webscan"), transport=transport,
        )
    semaphore = asyncio.Semaphore(max(1, concurrency))
    issues: list[DbIssue] = []
    done = 0

    async def worker(provider: Provider) -> None:
        nonlocal done
        async with semaphore:
            try:
                found = await check_provider(services, provider, scans.get(provider.id) if web else None)
            except Exception as exc:  # noqa: BLE001 — одна запись не должна ронять проверку всей базы
                found = [_issue(provider, "error", "check-failed", f"проверка не удалась: {exc}")]
            issues.extend(found)
            done += 1
            if progress:
                progress(done, len(providers))

    await asyncio.gather(*(worker(p) for p in providers))
    order = {"error": 0, "warn": 1, "info": 2}
    return sorted(issues, key=lambda i: (order[i.level], i.name.casefold(), i.code))
