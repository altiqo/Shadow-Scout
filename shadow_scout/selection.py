"""Отбор провайдеров по локациям.

Что решает модуль:
* план кандидатов — вместо обрезки списка «по алфавиту» берём лучших кандидатов на каждую локацию (по кругу, начиная
  с самых «бедных» локаций), чтобы потолок анализа делился между странами честно;
* «лучшие на локацию» — топ-N по оценке подбора, причём один и тот же провайдер не занимает все локации подряд
  (разнообразие), но и не оставляет локацию пустой, если альтернатив нет;
* финалисты для полной проверки (cheburcheck и др.) — только те, кто реально попадает в топ локации.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadow_scout.models import Location, LocationPick, Provider, RiskReport, SearchQuery

LocationKey = tuple[str, str | None]  # (страна, город)

# Чем меньше провайдер известен русскоязычному VPN-сообществу, тем меньше шанс, что его подсети уже в блок-листах.
POPULARITY_PRIOR = {1: 6.0, 2: 4.0, 3: 1.0, 4: -3.0, 5: -6.0}
SIZE_PRIOR = {"micro": 2.0, "small": 3.0, "medium": 1.0, "large": -2.0, "hyperscale": -6.0}
OVERSAMPLE = 3  # на каждую локацию берём в N раз больше кандидатов, чем покажем: быстрая проверка отсеет часть


@dataclass
class Plan:
    """Кого анализировать и почему именно их."""

    candidates: list[Provider] = field(default_factory=list)
    matched: int = 0  # сколько провайдеров подошло под фильтры
    groups: dict[LocationKey, int] = field(default_factory=dict)  # локация → сколько подходящих провайдеров в базе
    dropped: int = 0  # сколько подходящих не попало в анализ из-за потолка

    @property
    def thin_locations(self) -> list[LocationKey]:
        return sorted(k for k, n in self.groups.items() if n < 3)


def location_keys(provider: Provider, query: SearchQuery) -> list[LocationKey]:
    """Локации провайдера, попадающие под запрос (без фильтра по странам — все его локации)."""
    locations = provider.locations or ([Location(country=provider.hq_country)] if provider.hq_country != "ZZ" else [])
    if query.countries:
        wanted = {c.upper() for c in query.countries}
        locations = [loc for loc in locations if loc.country in wanted]
    keys: list[LocationKey] = []
    for loc in locations:
        key = (loc.country, loc.city if query.group_by == "city" else None)
        if key not in keys:
            keys.append(key)
    return keys


def prior_score(provider: Provider, query: SearchQuery, country: str) -> float:
    """Априорная привлекательность провайдера для локации — только по статичным данным (до анализа)."""
    score = POPULARITY_PRIOR.get(provider.popularity_ru, 0.0) + SIZE_PRIOR.get(provider.size, 0.0)
    if provider.hq_country == country:
        score += 3.0  # местный оператор, а не «присутствие» международной сети
    if provider.vps is True:
        score += 3.0
    if not provider.hints_only:
        score += 2.0  # запись составлена вручную — условия известны
    if provider.ip_type in ("isp", "mixed"):
        score += 1.0
    if provider.hourly is True:
        score += 3.0 if query.require_hourly else 1.0
    if provider.trial is True:
        score += 3.0 if query.require_trial else 1.0
    if provider.ru_ties:
        score -= 5.0
    if provider.min_price_eur is not None and provider.min_price_eur <= 10:
        score += 0.5
    return score


def plan_candidates(providers: list[Provider], query: SearchQuery) -> Plan:
    """Выбирает кандидатов на анализ: лучших на каждую локацию, а не первых по алфавиту."""
    per_location = max(1, query.per_location)
    quota = max(per_location * OVERSAMPLE, per_location + 4)
    cap = max(1, query.limit)

    ranked: dict[LocationKey, list[Provider]] = {}
    for provider in providers:
        for key in location_keys(provider, query):
            ranked.setdefault(key, []).append(provider)
    for key, items in ranked.items():
        items.sort(key=lambda p, c=key[0]: (-prior_score(p, query, c), p.name.casefold(), p.id))

    plan = Plan(matched=len(providers), groups={key: len(items) for key, items in ranked.items()})
    union = {p.id for items in ranked.values() for p in items}
    selected: dict[str, Provider] = {}
    order = sorted(ranked, key=lambda k: (len(ranked[k]), k[0], k[1] or ""))  # сначала локации с наименьшим выбором
    for rank in range(quota):
        for key in order:
            items = ranked[key]
            if rank < len(items) and items[rank].id not in selected:
                selected[items[rank].id] = items[rank]
                if len(selected) >= cap:
                    break
        if len(selected) >= cap:
            break
    plan.candidates = list(selected.values())
    plan.dropped = len(union) - len(plan.candidates)
    return plan


def pick_score(report: RiskReport, country: str, query: SearchQuery) -> float:
    """Оценка для ранжирования внутри локации: выживаемость с поправкой на полноту данных и пригодность к аренде."""
    p = report.provider
    base = 40.0 if report.verdict == "unknown" else report.survivability
    # быстрая проверка не видит cheburcheck → меньше уверенность → закономерно не обгоняет полностью проверенных
    score = base * (0.6 + 0.4 * report.confidence)
    if p.hq_country == country:
        score += 3.0
    if p.vps is True:
        score += 2.0
    elif p.vps is None:
        score -= 2.0
    if p.hints_only:
        score -= 1.0
    if p.hourly is True:
        score += 6.0 if query.require_hourly else 1.5
    if p.trial is True:
        score += 6.0 if query.require_trial else 1.5
    return score


def build_picks(
    reports: list[RiskReport],
    query: SearchQuery,
    per_location: int | None = None,
    group_counts: dict[LocationKey, int] | None = None,
) -> list[LocationPick]:
    """Топ провайдеров на каждую локацию.

    Разнообразие: провайдер попадает в «лучшие» не более чем в ``query.max_repeat`` локациях, пока есть альтернативы;
    если альтернатив не хватает, повторы всё же допускаются — пустая локация хуже повтора.
    """
    n = max(1, per_location or query.per_location)
    max_repeat = query.max_repeat if query.max_repeat > 0 else 10**6
    eligible: dict[LocationKey, list[RiskReport]] = {}
    analyzed: dict[LocationKey, int] = {}  # сколько проанализировано в локации, включая критичных
    for report in reports:
        for key in location_keys(report.provider, query):
            analyzed[key] = analyzed.get(key, 0) + 1
            if report.verdict != "critical":
                eligible.setdefault(key, []).append(report)
    for key in analyzed:
        eligible.setdefault(key, [])
    for key, items in eligible.items():
        items.sort(key=lambda r, c=key[0]: (-pick_score(r, c, query), r.provider.name.casefold(), r.provider.id))

    used: dict[str, int] = {}
    chosen: dict[LocationKey, list[RiskReport]] = {key: [] for key in eligible}
    # локации с меньшим выбором обслуживаем первыми — им «общие» провайдеры нужнее всего
    order = sorted(eligible, key=lambda k: (len(eligible[k]), k[0], k[1] or ""))
    for key in order:
        for r in eligible[key]:
            if len(chosen[key]) >= n:
                break
            if used.get(r.provider.id, 0) < max_repeat:
                chosen[key].append(r)
                used[r.provider.id] = used.get(r.provider.id, 0) + 1
    for key in order:  # добор повторами, если альтернатив не хватило
        for r in eligible[key]:
            if len(chosen[key]) >= n:
                break
            if r not in chosen[key]:
                chosen[key].append(r)
    if query.countries:
        position = {c.upper(): i for i, c in enumerate(query.countries)}
    else:
        position = {}
    # запрошенные страны без единого подходящего провайдера тоже показываем — «пусто» лучше, чем молчаливое отсутствие блока
    if query.group_by == "country":
        for cc in position:
            if (cc, None) not in chosen:
                chosen[(cc, None)] = []
    keys = sorted(chosen, key=lambda k: (position.get(k[0], 10**6), k[0], k[1] or ""))
    return [
        LocationPick(
            country=key[0],
            city=key[1],
            provider_ids=[r.provider.id for r in sorted(chosen[key], key=lambda r, c=key[0]: (-pick_score(r, c, query), r.provider.name.casefold()))],
            candidates=(group_counts or {}).get(key, analyzed.get(key, 0)),
            analyzed=analyzed.get(key, 0),
        )
        for key in keys
    ]


def deep_targets(reports: list[RiskReport], query: SearchQuery) -> list[str]:
    """Кого из быстро проверенных нужно проверить полностью: тех, кто сейчас в топе своей локации."""
    if query.deep_per_location <= 0:
        return []
    by_id = {r.provider.id: r for r in reports}
    picks = build_picks(reports, query, per_location=query.deep_per_location)
    need: list[str] = []
    for pick in picks:
        for pid in pick.provider_ids:
            if by_id[pid].depth == "quick" and pid not in need:
                need.append(pid)
    return need


def filter_reports(reports: list[RiskReport], query: SearchQuery) -> list[RiskReport]:
    """Пост-фильтры по результатам анализа: допустимый риск и размер сети."""
    out = reports
    if query.max_risk:
        order = ["low", "moderate", "high", "critical", "unknown"]
        limit = order.index(query.max_risk)
        out = [r for r in out if r.verdict == "unknown" or order.index(r.verdict) <= limit]
    if query.max_asn_ipv4:
        out = [r for r in out if not r.total_ipv4 or r.total_ipv4 <= query.max_asn_ipv4]
    return out
