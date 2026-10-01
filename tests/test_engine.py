from __future__ import annotations

from pathlib import Path

import pytest

from shadow_scout.analysis.engine import AnalysisEngine, holder_matches
from shadow_scout.export import export_many
from shadow_scout.models import Location, Provider, SearchQuery
from shadow_scout.providers import ProviderDB, load_countries


def make_provider(**kw) -> Provider:
    base = dict(id="glesys", name="GleSYS", website="https://glesys.com", asns=[42708], hq_country="SE", locations=[Location(country="SE", city="Stockholm")], size="small", popularity_ru=1, ip_type="dch", trial=False, hourly=True, min_price_eur=5)
    base.update(kw)
    return Provider(**base)


async def test_clean_small_provider_scores_low_risk(services):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    report = await engine.analyze(make_provider(), SearchQuery(countries=["SE"]))
    assert report.asns and report.asns[0].holder == "GLESYS-AS"
    assert report.asns[0].blocked_ipv4_count == 0
    assert report.verdict == "low", report.signals
    assert report.survivability >= 80
    assert report.confidence > 0.6
    sig = {s.key: s for s in report.signals}
    assert sig["blocklist_overlap"].risk == 0
    assert sig["cheburcheck_asn"].risk == 0
    assert sig["network_type"].risk <= 0.5


async def test_heavily_blocked_provider_is_critical(services):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    hetzner = make_provider(id="hetzner", name="Hetzner", website="https://www.hetzner.com", asns=[24940], hq_country="DE", locations=[Location(country="DE", city="Falkenstein")], size="hyperscale", popularity_ru=5)
    report = await engine.analyze(hetzner)
    assert report.verdict == "critical"
    assert report.hard_flags
    assert report.blocked_share > 0.4
    assert report.signal("complaints").risk > 0


async def test_asn_resolution_by_search(services):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    provider = make_provider(id="hostup", name="Hostup", website="https://hostup.se", asns=[], asn_search="Hostup")
    asns, how = await engine.resolve_asns(provider)
    assert asns == [12345]
    assert how == "search"
    # второй вызов берётся из кеша
    asns2, how2 = await engine.resolve_asns(provider)
    assert asns2 == [12345] and how2 == "cache"


async def test_cheburcheck_outage_degrades_gracefully(services, fake_api):
    fake_api.cheburcheck_down = True
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    report = await engine.analyze(make_provider())
    cc = report.signal("cheburcheck_asn")
    assert cc.status.value == "unavailable"
    assert report.verdict in ("low", "moderate")
    assert report.confidence < 1


async def test_run_search_and_export(services, tmp_path: Path):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    providers = [
        make_provider(),
        make_provider(id="hetzner", name="Hetzner", website="https://www.hetzner.com", asns=[24940], hq_country="DE", locations=[Location(country="DE")], size="hyperscale", popularity_ru=5),
        make_provider(id="unknown", name="Mystery Host", website=None, asns=[], asn_search="Nonexistent Corp"),
    ]
    result = await engine.run_search(providers, SearchQuery(countries=["SE", "DE"]), title="Тест")
    assert len(result.reports) == 3
    ordered = result.sorted_reports()
    assert ordered[0].provider.id == "glesys"
    assert ordered[1].provider.id == "hetzner"
    assert ordered[-1].provider.id == "unknown"
    assert ordered[-1].verdict == "unknown"
    paths = export_many(result, ["html", "pdf", "xlsx", "csv", "md", "json"], tmp_path / "out", "report")
    for p in paths:
        assert p.exists() and p.stat().st_size > 500, p
    html = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "GleSYS" in html and "Shadow Scout" in html


async def test_analyze_adhoc_targets(services):
    await services.ensure_blocklists()
    engine = AnalysisEngine(services)
    report = await engine.analyze_target("AS24940")
    assert report.provider.asns == [24940]
    assert report.verdict in ("high", "critical")
    report_ip = await engine.analyze_target("5.9.1.1")
    assert report_ip.provider.asns == [24940]
    report_dom = await engine.analyze_target("example.org")
    assert report_dom.provider.website == "https://example.org"


def test_holder_matching():
    p = make_provider(name="GleSYS", website="https://glesys.com")
    assert holder_matches(p, "GLESYS-AS GleSYS AB") is True
    assert holder_matches(p, "HETZNER-AS") is False
    assert holder_matches(p, None) is None


def test_bundled_database_is_consistent():
    db = ProviderDB()
    providers = db.all(include_disabled=True)
    assert len(providers) > 100
    ids = [p.id for p in providers]
    assert len(ids) == len(set(ids))
    countries = load_countries()
    for p in providers:
        assert p.asns or p.asn_search, p.id
        for loc in p.locations:
            assert countries.get(loc.country).name_ru != loc.country or loc.country in countries.countries, (p.id, loc)
    filtered = db.filter(SearchQuery(countries=["SE"], require_hourly=True))
    assert any(p.id == "glesys" for p in filtered)
    assert all(not p.ru_ties for p in db.filter(SearchQuery()))


@pytest.mark.parametrize("fmt", ["html", "pdf", "xlsx", "csv", "md", "json"])
async def test_export_each_format_with_empty_result(services, tmp_path: Path, fmt: str):
    from shadow_scout.export import export
    from shadow_scout.models import SearchResult

    result = SearchResult(query=SearchQuery(), reports=[], sources=[])
    path = export(result, fmt, tmp_path, "empty")
    assert path.exists()
