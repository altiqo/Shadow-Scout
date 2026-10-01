"""Отбор по локациям: честный план кандидатов вместо обрезки по алфавиту, разнообразие «лучших», финалисты."""

from __future__ import annotations

from shadow_scout import selection
from shadow_scout.models import Location, Provider, RiskReport, SearchQuery


def prov(pid: str, countries: list[str], hq: str | None = None, **kw) -> Provider:
    base = dict(
        id=pid, name=pid.upper(), website=f"https://{pid}.example", asns=[64500], hq_country=hq or countries[0],
        locations=[Location(country=c, city=f"{c}-city") for c in countries], size="small", popularity_ru=1, ip_type="dch",
        vps=True,
    )
    base.update(kw)
    return Provider(**base)


def report(p: Provider, survivability: float = 90, verdict: str = "low", confidence: float = 1.0, depth: str = "full") -> RiskReport:
    return RiskReport(provider=p, survivability=survivability, risk_score=100 - survivability, verdict=verdict, confidence=confidence, depth=depth)


def many(countries: list[str], per_country: int) -> list[Provider]:
    return [prov(f"{cc.lower()}{i:02d}", [cc]) for cc in countries for i in range(per_country)]


# ───────────────────────── план кандидатов ─────────────────────────
def test_plan_covers_every_location_not_alphabet():
    """Раньше 25 первых по алфавиту «съедали» весь лимит: страны, названия которых в конце списка, оставались без кандидатов."""
    providers = many(["AT", "BE", "CZ", "DK", "EE", "FI"], 12)  # 72 провайдера
    query = SearchQuery(countries=["AT", "BE", "CZ", "DK", "EE", "FI"], per_location=3, limit=30)
    plan = selection.plan_candidates(providers, query)
    assert len(plan.candidates) == 30
    covered = {loc.country for p in plan.candidates for loc in p.locations}
    assert covered == {"AT", "BE", "CZ", "DK", "EE", "FI"}
    for cc in covered:
        assert sum(1 for p in plan.candidates if p.hq_country == cc) == 5  # потолок поделен поровну
    assert plan.matched == 72 and plan.dropped == 42


def test_plan_serves_scarce_locations_first():
    providers = many(["SE"], 20) + many(["IS"], 2)
    query = SearchQuery(countries=["SE", "IS"], per_location=5, limit=6)
    plan = selection.plan_candidates(providers, query)
    assert {p.hq_country for p in plan.candidates} == {"SE", "IS"}
    assert sum(1 for p in plan.candidates if p.hq_country == "IS") == 2  # у «бедной» локации берём всех
    assert plan.groups[("IS", None)] == 2 and ("IS", None) in plan.thin_locations


def test_plan_prefers_local_small_confirmed_over_big_unconfirmed():
    big = prov("bigco", ["SE", "FI"], hq="US", size="large", popularity_ru=4, vps=None)
    local = prov("localco", ["SE"], hq="SE")
    unknown_local = prov("unknownco", ["SE"], hq="SE", vps=None, source="catalog")
    query = SearchQuery(countries=["SE"], per_location=1, limit=1)
    plan = selection.plan_candidates([big, unknown_local, local], query)
    assert [p.id for p in plan.candidates] == ["localco"]


def test_plan_without_countries_groups_by_all_locations():
    providers = [prov("a", ["SE", "FI"]), prov("b", ["NO"])]
    plan = selection.plan_candidates(providers, SearchQuery(per_location=1))
    assert set(plan.groups) == {("SE", None), ("FI", None), ("NO", None)}
    assert {p.id for p in plan.candidates} == {"a", "b"}


def test_plan_group_by_city():
    p = Provider(id="x", name="X", asns=[1], hq_country="SE", locations=[Location(country="SE", city="Stockholm"), Location(country="SE", city="Falkenberg")])
    plan = selection.plan_candidates([p], SearchQuery(countries=["SE"], group_by="city"))
    assert set(plan.groups) == {("SE", "Stockholm"), ("SE", "Falkenberg")}


def test_plan_is_deterministic_and_case_insensitive():
    providers = [prov("b1", ["SE"], name="beta"), prov("a1", ["SE"], name="Alpha"), prov("c1", ["SE"], name="alpha2")]
    query = SearchQuery(countries=["SE"], per_location=3, limit=3)
    first = [p.id for p in selection.plan_candidates(providers, query).candidates]
    second = [p.id for p in selection.plan_candidates(list(reversed(providers)), query).candidates]
    assert first == second == ["a1", "c1", "b1"]  # «Alpha» < «alpha2» < «beta» без учёта регистра


def test_prior_rewards_required_flags():
    hourly = prov("h", ["SE"], hourly=True)
    plain = prov("p", ["SE"])
    q_plain = SearchQuery(countries=["SE"])
    q_hourly = SearchQuery(countries=["SE"], require_hourly=True)
    assert selection.prior_score(hourly, q_hourly, "SE") - selection.prior_score(plain, q_hourly, "SE") > selection.prior_score(hourly, q_plain, "SE") - selection.prior_score(plain, q_plain, "SE")


# ───────────────────────── лучшие на локацию ─────────────────────────
def test_default_is_one_location_per_provider():
    """По умолчанию один хостер не повторяется в разных локациях, если есть альтернативы (жалоба «везде один и тот же»)."""
    assert SearchQuery().max_repeat == 1
    star = prov("star", ["SE", "FI", "NO"], hq="SE")
    reports = [report(star, 99)] + [report(prov(f"{cc.lower()}{i}", [cc]), 80) for cc in ("SE", "FI", "NO") for i in range(2)]
    picks = selection.build_picks(reports, SearchQuery(countries=["SE", "FI", "NO"], per_location=2))
    assert sum("star" in pick.provider_ids for pick in picks) == 1


def test_picks_limit_repeats_of_multi_location_provider():
    """Один мультилокационный хостер лидирует везде — но «лучшим» его показываем лишь в max_repeat локациях."""
    star = prov("star", ["SE", "FI", "NO"], hq="SE")
    locals_ = [prov(f"{cc.lower()}{i}", [cc]) for cc in ("SE", "FI", "NO") for i in range(3)]
    reports = [report(star, 99)] + [report(p, 80) for p in locals_]
    query = SearchQuery(countries=["SE", "FI", "NO"], per_location=2, max_repeat=1)
    picks = selection.build_picks(reports, query)
    featured = [pick.country for pick in picks if "star" in pick.provider_ids]
    assert len(featured) == 1
    assert all(len(pick.provider_ids) == 2 for pick in picks)


def test_picks_unlimited_repeats_when_zero():
    star = prov("star", ["SE", "FI", "NO"], hq="SE")
    reports = [report(star, 99)] + [report(prov(f"{cc.lower()}0", [cc]), 80) for cc in ("SE", "FI", "NO")]
    picks = selection.build_picks(reports, SearchQuery(countries=["SE", "FI", "NO"], per_location=2, max_repeat=0))
    assert all("star" in pick.provider_ids for pick in picks)


def test_picks_allow_repeats_rather_than_leave_location_empty():
    star = prov("star", ["SE", "FI"], hq="SE")
    picks = selection.build_picks([report(star, 99)], SearchQuery(countries=["SE", "FI"], per_location=3, max_repeat=1))
    assert {pick.country: pick.provider_ids for pick in picks} == {"SE": ["star"], "FI": ["star"]}


def test_picks_scarce_location_gets_shared_provider_first():
    """Если альтернатив мало, «общий» провайдер достаётся локации с наименьшим выбором."""
    shared = prov("shared", ["IS", "SE"], hq="IS")
    se = [prov(f"se{i}", ["SE"]) for i in range(4)]
    picks = selection.build_picks([report(shared, 95)] + [report(p, 85) for p in se], SearchQuery(countries=["IS", "SE"], per_location=2, max_repeat=1))
    by_cc = {pick.country: pick.provider_ids for pick in picks}
    assert "shared" in by_cc["IS"] and "shared" not in by_cc["SE"]


def test_picks_skip_critical_and_rank_unknown_last():
    good, meh, bad, unknown = (prov(n, ["SE"]) for n in ("good", "meh", "bad", "unk"))
    reports = [report(good, 90), report(meh, 55, "high"), report(bad, 10, "critical"), report(unknown, 100, "unknown", confidence=0.0)]
    pick = selection.build_picks(reports, SearchQuery(countries=["SE"], per_location=5))[0]
    assert pick.provider_ids == ["good", "meh", "unk"]  # critical отсутствует; «нет данных» (survivability=100) не обгоняет оценённых


def test_picks_prefer_local_operator_and_confirmed_flags():
    local = prov("local", ["SE"], hq="SE")
    foreign = prov("foreign", ["SE"], hq="DE")
    pick = selection.build_picks([report(foreign, 90), report(local, 90)], SearchQuery(countries=["SE"], per_location=2))[0]
    assert pick.provider_ids[0] == "local"
    hourly = prov("hourly", ["SE"], hq="SE", hourly=True)
    plain = prov("plain", ["SE"], hq="SE")
    pick = selection.build_picks([report(plain, 92), report(hourly, 90)], SearchQuery(countries=["SE"], per_location=2, require_hourly=True))[0]
    assert pick.provider_ids[0] == "hourly"  # подтверждённая почасовая важнее пары пунктов выживаемости


def test_picks_discount_low_confidence():
    solid = prov("solid", ["SE"])
    guess = prov("guess", ["SE"])
    pick = selection.build_picks([report(guess, 95, confidence=0.3), report(solid, 85, confidence=1.0)], SearchQuery(countries=["SE"], per_location=2))[0]
    assert pick.provider_ids == ["solid", "guess"]


def test_picks_show_empty_locations_with_reason():
    """Локация, где рекомендовать некого, не должна молча пропадать: «пусто» — тоже ответ."""
    only_critical = prov("bad", ["IS"])
    reports = [report(only_critical, 10, "critical"), report(prov("ok", ["SE"]), 90)]
    picks = selection.build_picks(reports, SearchQuery(countries=["SE", "IS", "HR"], per_location=3), group_counts={("HR", None): 0})
    by_cc = {p.country: p for p in picks}
    assert [p.country for p in picks] == ["SE", "IS", "HR"]
    assert by_cc["SE"].provider_ids == ["ok"]
    assert by_cc["IS"].provider_ids == [] and by_cc["IS"].analyzed == 1  # проанализирован, но критичен
    assert by_cc["HR"].provider_ids == [] and by_cc["HR"].candidates == 0 and by_cc["HR"].analyzed == 0  # в базе никого


def test_picks_analyzed_counts_critical_too():
    reports = [report(prov("a", ["SE"]), 90), report(prov("b", ["SE"]), 5, "critical")]
    pick = selection.build_picks(reports, SearchQuery(countries=["SE"]))[0]
    assert pick.provider_ids == ["a"] and pick.analyzed == 2


def test_picks_counts_and_order_follow_query():
    reports = [report(prov("a", ["NO"]), 90), report(prov("b", ["SE"]), 90), report(prov("c", ["SE"]), 80)]
    picks = selection.build_picks(reports, SearchQuery(countries=["SE", "NO"], per_location=5), group_counts={("SE", None): 7})
    assert [p.country for p in picks] == ["SE", "NO"]  # порядок стран из запроса
    se = picks[0]
    assert se.candidates == 7 and se.analyzed == 2


# ───────────────────────── финалисты и фильтры ─────────────────────────
def test_deep_targets_are_quick_reports_in_top_of_location():
    ps = [prov(f"p{i}", ["SE"]) for i in range(5)]
    reports = [report(p, 90 - i, depth="quick") for i, p in enumerate(ps)]
    reports[0] = report(ps[0], 90, depth="full")
    need = selection.deep_targets(reports, SearchQuery(countries=["SE"], deep_per_location=3))
    assert need == ["p1", "p2"]  # p0 уже проверен полностью, p3/p4 не в топ-3


def test_deep_targets_disabled():
    reports = [report(prov("a", ["SE"]), depth="quick")]
    assert selection.deep_targets(reports, SearchQuery(countries=["SE"], deep_per_location=0)) == []


def test_filter_reports_by_risk_and_size():
    from shadow_scout.models import AsnInfo

    small = report(prov("small", ["SE"]), verdict="low")
    small.asns = [AsnInfo(asn=1, ipv4_count=1024)]
    big = report(prov("big", ["SE"]), verdict="high")
    big.asns = [AsnInfo(asn=2, ipv4_count=500_000)]
    unknown = report(prov("unk", ["SE"]), verdict="unknown")
    out = selection.filter_reports([small, big, unknown], SearchQuery(max_risk="moderate", max_asn_ipv4=100_000))
    assert [r.provider.id for r in out] == ["small", "unk"]
