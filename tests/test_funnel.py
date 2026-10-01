"""Двухфазный анализ: быстрая проверка по локальным данным для всех, полная — только для лучших на локацию."""

from __future__ import annotations

from shadow_scout import selection
from shadow_scout.analysis.engine import FULL_ANALYSIS_MAX, AnalysisEngine, ProgressHooks
from shadow_scout.models import Location, Provider, SearchQuery

# ASN, которые умеет отдавать поддельный API (см. conftest.ASN_DATA)
KNOWN_ASNS = [42708, 200651, 202053, 99999]


def make_providers(countries: list[str], per_country: int) -> list[Provider]:
    out = []
    for cc in countries:
        for i in range(per_country):
            asn = KNOWN_ASNS[i % len(KNOWN_ASNS)]
            out.append(Provider(
                id=f"{cc.lower()}{i:02d}", name=f"{cc}-host-{i:02d}", website=f"https://{cc.lower()}{i:02d}.example", asns=[asn],
                hq_country=cc, locations=[Location(country=cc)], size="small", popularity_ru=1, vps=True,
            ))
    return out


def calls_to(api, needle: str) -> list[str]:
    return [c for c in api.calls if needle in c]


async def test_quick_analysis_makes_no_external_requests(services, fake_api):
    await services.ensure_blocklists()
    fake_api.calls.clear()
    report = await AnalysisEngine(services).analyze(make_providers(["SE"], 1)[0], SearchQuery(countries=["SE"]), mode="quick")
    assert report.depth == "quick" and report.asns and report.asns[0].ipv4_count > 0
    for needle in ("cheburcheck.ru", "ip-api.com", "peeringdb.com", "as-overview"):
        assert not calls_to(fake_api, needle), needle
    sig = {s.key: s for s in report.signals}
    assert sig["cheburcheck_asn"].status.value == "unavailable" and "быстрая" in sig["cheburcheck_asn"].summary
    assert sig["blocklist_overlap"].status.value == "ok"  # локальные списки работают
    assert report.confidence < 1.0  # честно: полнота данных ниже, чем у полной проверки


async def test_full_analysis_after_quick_reuses_prefixes(services, fake_api):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    provider = make_providers(["SE"], 1)[0]
    quick = await engine.analyze(provider, mode="quick")
    fake_api.calls.clear()
    full = await engine.analyze(provider, mode="full", previous=quick)
    assert full.depth == "full" and full.asns[0].holder  # холдер и PeeringDB добавлены
    assert not calls_to(fake_api, "announced-prefixes") and not calls_to(fake_api, "asn-ip")  # префиксы не запрашивались заново
    assert calls_to(fake_api, "cheburcheck.ru")
    assert full.confidence > quick.confidence


async def test_small_runs_are_analyzed_fully(services):
    await services.ensure_blocklists()
    providers = make_providers(["SE"], FULL_ANALYSIS_MAX)
    result = await AnalysisEngine(services).run_search(providers, SearchQuery(countries=["SE"]))
    assert len(result.reports) == FULL_ANALYSIS_MAX and all(r.depth == "full" for r in result.reports)


async def test_large_runs_deepen_only_top_of_each_location(services):
    await services.ensure_blocklists()
    providers = make_providers(["SE", "FI"], 10)
    query = SearchQuery(countries=["SE", "FI"], per_location=3, deep_per_location=2)
    phases: list[tuple[str, int]] = []
    engine = AnalysisEngine(services, ProgressHooks(on_phase=lambda name, total: phases.append((name, total))))
    result = await engine.run_search(providers, query, plan=selection.plan_candidates(providers, query))
    full = [r for r in result.reports if r.depth == "full"]
    quick = [r for r in result.reports if r.depth == "quick"]
    assert len(result.reports) == 20 and quick and 4 <= len(full) < 20
    assert phases[0] == ("quick", 20) and phases[1][0] == "deep"
    for pick in result.picks:
        top = [result.report_by_id(pid) for pid in pick.provider_ids[:2]]
        assert all(r.depth == "full" for r in top), pick  # лучшие в каждой локации проверены полностью
    assert result.candidates_analyzed == 20 and result.candidates_total == 20


async def test_quick_only_mode_never_touches_cheburcheck(services, fake_api):
    await services.ensure_blocklists()
    providers = make_providers(["SE"], 15)
    result = await AnalysisEngine(services).run_search(providers, SearchQuery(countries=["SE"], deep_per_location=0))
    assert all(r.depth == "quick" for r in result.reports) and result.picks
    assert not calls_to(fake_api, "cheburcheck.ru")


async def test_deep_phase_promotes_next_candidate_when_leaders_collapse(services, monkeypatch):
    """Лидеры по быстрой проверке «просели» после полной → в топ поднимаются следующие, и их тоже проверяют полностью."""
    from shadow_scout.models import RiskReport

    engine = AnalysisEngine(services)
    analyzed: list[tuple[str, str]] = []

    async def scripted(provider, query=None, mode="full", previous=None):
        idx = int(provider.id[2:])
        analyzed.append((provider.id, mode))
        if mode == "quick":
            return RiskReport(provider=provider, survivability=95 - idx, risk_score=5 + idx, verdict="low", confidence=0.7, depth="quick")
        collapsed = idx < 2  # p00 и p01 на деле заблокированы
        return RiskReport(
            provider=provider, survivability=5 if collapsed else 95 - idx, risk_score=95 if collapsed else 5 + idx,
            verdict="critical" if collapsed else "low", confidence=1.0, depth="full",
        )

    monkeypatch.setattr(engine, "analyze", scripted)
    providers = make_providers(["SE"], 14)
    query = SearchQuery(countries=["SE"], per_location=3, deep_per_location=3)
    result = await engine.run_search(providers, query)
    pick = result.picks[0]
    assert pick.provider_ids == ["se02", "se03", "se04"]
    assert all(result.report_by_id(pid).depth == "full" for pid in pick.provider_ids)
    deep_order = [pid for pid, mode in analyzed if mode == "full"]
    assert deep_order[:3] == ["se00", "se01", "se02"]  # первый раунд — топ-3 по быстрой проверке
    assert set(deep_order[3:]) == {"se03", "se04"}  # второй раунд — те, кто занял освободившиеся места
    assert len(deep_order) == 5  # остальных не трогали: полная проверка дорогая


async def test_max_risk_and_size_filters_apply_before_picks(services):
    await services.ensure_blocklists()
    providers = make_providers(["SE"], 13)
    hetzner = Provider(id="hz", name="Hetzner", asns=[24940], hq_country="SE", locations=[Location(country="SE")], size="small", popularity_ru=1, vps=True)
    query = SearchQuery(countries=["SE"], per_location=20, max_risk="moderate")
    result = await AnalysisEngine(services).run_search(providers + [hetzner], query)
    assert "hz" not in {r.provider.id for r in result.reports}  # критичный провайдер отфильтрован
    assert "hz" not in {pid for pick in result.picks for pid in pick.provider_ids}


async def test_errors_in_one_provider_do_not_break_search(services, monkeypatch):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    original = engine.analyze

    async def flaky(provider, query=None, mode="full", previous=None):
        if provider.id == "se01":
            raise RuntimeError("boom")
        return await original(provider, query, mode, previous)

    monkeypatch.setattr(engine, "analyze", flaky)
    result = await engine.run_search(make_providers(["SE"], 3), SearchQuery(countries=["SE"]))
    broken = result.report_by_id("se01")
    assert broken is not None and "boom" in broken.warnings[0] and broken.verdict == "unknown"
    assert len(result.reports) == 3


async def test_discovery_style_queries_fully_check_every_chosen_candidate(services):
    """Кандидатов discovery пользователь выбрал вручную — полная проверка нужна всем, даже если их больше порога."""
    await services.ensure_blocklists()
    providers = make_providers(["SE"], 15)
    query = SearchQuery(countries=["SE"], include_ru_ties=True, per_location=len(providers), deep_per_location=len(providers))
    result = await AnalysisEngine(services).run_search(providers, query)
    assert len(result.reports) == 15 and all(r.depth == "full" for r in result.reports)
