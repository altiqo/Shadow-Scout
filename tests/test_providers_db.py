"""База провайдеров: приоритеты источников, дубли, «нет» против «неизвестно», фильтры, статистика."""

from __future__ import annotations

import pytest

from shadow_scout import providers as providers_mod
from shadow_scout.harvest.catalog_io import write_catalog
from shadow_scout.models import Location, Provider, SearchQuery
from shadow_scout.providers import ProviderDB, _parse_providers


def prov(pid: str, countries: list[str] = ("SE",), source: str = "bundled", **kw) -> Provider:
    base = dict(
        id=pid, name=pid.title(), website=f"https://{pid}.example", asns=[1000 + sum(ord(ch) for ch in pid)], hq_country=countries[0],
        locations=[Location(country=c) for c in countries], source=source, vps=True if source != "catalog" else None,
    )
    base.update(kw)
    return Provider(**base)


def make_db(bundled=(), catalog=(), user=(), disabled=()) -> ProviderDB:
    db = ProviderDB.__new__(ProviderDB)  # без чтения файлов
    db.include_catalog = True
    db.bundled, db.catalog, db.user = list(bundled), list(catalog), list(user)
    db.disabled_ids = set(disabled)
    db._merged = None
    return db


# ───────────────────────── слияние источников ─────────────────────────
def test_precedence_user_over_curated_over_catalog_by_id():
    catalog = prov("same", source="catalog", name="From catalog", asns=[1])
    curated = prov("same", name="Curated", asns=[2])
    user = prov("same", source="user", name="Mine", asns=[3])
    assert make_db(catalog=[catalog]).get("same").name == "From catalog"
    assert make_db(bundled=[curated], catalog=[catalog]).get("same").name == "Curated"
    assert make_db(bundled=[curated], catalog=[catalog], user=[user]).get("same").name == "Mine"


def test_catalog_entry_dropped_when_it_duplicates_curated_by_asn_or_domain():
    curated = prov("glesys", asns=[42708], website="https://glesys.com")
    same_asn = prov("glesys-ab", source="catalog", asns=[42708, 99], website="https://other.example")
    same_domain = prov("glesys-2", source="catalog", asns=[555], website="https://www.glesys.com/")
    unrelated = prov("unrelated", source="catalog", asns=[777])
    ids = {p.id for p in make_db(bundled=[curated], catalog=[same_asn, same_domain, unrelated]).all()}
    assert ids == {"glesys", "unrelated"}


def test_catalog_entry_on_a_subdomain_of_a_curated_site_is_a_duplicate():
    """«Aruba S.p.A» с сайтом staff.aruba.it — тот же провайдер, что и ручная запись aruba.it."""
    curated = prov("aruba", asns=[31034], website="https://www.aruba.it")
    staff = prov("aruba-spa", source="catalog", asns=[199883], website="https://staff.aruba.it")
    co_uk = prov("host-uk", source="catalog", asns=[5], website="https://shop.hostco.co.uk")
    curated_uk = prov("hostco", asns=[6], website="https://www.hostco.co.uk")
    other = prov("arubaclone", source="catalog", asns=[7], website="https://aruba.example")
    ids = {p.id for p in make_db(bundled=[curated, curated_uk], catalog=[staff, co_uk, other]).all()}
    assert ids == {"aruba", "hostco", "arubaclone"}


def test_registrable_domain():
    from shadow_scout.models import registrable_domain

    assert registrable_domain("staff.aruba.it") == "aruba.it" and registrable_domain("www.host.co.uk") == "host.co.uk"
    assert registrable_domain("example.com") == "example.com" and registrable_domain(None) is None


def test_all_is_sorted_case_insensitively_and_disabled_hidden():
    db = make_db(bundled=[prov("b", name="beta"), prov("a", name="Alpha"), prov("c", name="alpha2"), prov("d", name="Delta")], disabled=["d"])
    assert [p.name for p in db.all()] == ["Alpha", "alpha2", "beta"]
    assert len(db.all(include_disabled=True)) == 4


def test_parse_sets_vps_default_only_for_manual_sources():
    item = {"id": "x", "name": "X", "asns": [1], "hq_country": "SE"}
    assert _parse_providers([item], "bundled")[0].vps is True
    assert _parse_providers([item], "user")[0].vps is True
    assert _parse_providers([item], "catalog")[0].vps is None
    assert _parse_providers([{**item, "vps": False}], "bundled")[0].vps is False
    assert _parse_providers([{"id": "broken", "size": "gigantic"}, item], "bundled")[0].id == "x"  # битая запись не ломает остальные


def test_discovered_candidates_stay_unverified_when_saved_to_user_db(tmp_path, monkeypatch):
    """Кандидат discovery — не обязательно продавец VPS (это может быть обычный ISP): «неизвестно» не должно превращаться в «да»."""
    monkeypatch.setattr(providers_mod, "user_providers_file", lambda: tmp_path / "user.yaml")
    db = make_db()
    db.add_user(Provider(id="as1", name="Some ISP", asns=[1], hq_country="SE", source="discovered", tags=["discovered", "local"]))
    db.add_user(Provider(id="mine", name="Mine", asns=[2], hq_country="SE"))
    assert db.get("as1").vps is None and db.get("mine").vps is True
    reloaded = make_db()
    reloaded.user = providers_mod._parse_providers(providers_mod.load_yaml(tmp_path / "user.yaml"), "user")
    assert {p.id: p.vps for p in reloaded.user} == {"as1": None, "mine": True}


def test_catalog_user_file_overrides_bundled_by_asn(tmp_path, monkeypatch):
    bundled_file = write_catalog([prov("old-a", source="catalog", asns=[1]), prov("keep-b", source="catalog", asns=[2])], tmp_path / "bundled.json")
    user_file = write_catalog([prov("new-a", source="catalog", asns=[1, 5])], tmp_path / "user.json")
    monkeypatch.setattr(providers_mod, "CATALOG_FILE", bundled_file)
    monkeypatch.setattr(providers_mod, "user_catalog_file", lambda: user_file)
    assert sorted(p.id for p in providers_mod._load_catalog()) == ["keep-b", "new-a"]
    monkeypatch.setattr(providers_mod, "user_catalog_file", lambda: tmp_path / "absent.json")
    assert sorted(p.id for p in providers_mod._load_catalog()) == ["keep-b", "old-a"]


# ───────────────────────── фильтры ─────────────────────────
def test_unknown_flags_pass_leniently_but_not_strictly():
    yes, unknown, no = prov("yes", hourly=True), prov("unk", source="catalog", hourly=None), prov("no", hourly=False)
    db = make_db(bundled=[yes, no], catalog=[unknown])
    lenient = {p.id for p in db.filter(SearchQuery(require_hourly=True))}
    strict = {p.id for p in db.filter(SearchQuery(require_hourly=True, strict_flags=True))}
    assert lenient == {"yes", "unk"}  # явное «нет» отсекается, «неизвестно» — нет
    assert strict == {"yes"}
    assert {p.id for p in db.filter(SearchQuery())} == {"yes", "unk", "no"}  # без требований флаги не важны


def test_trial_filter_uses_same_semantics():
    trial, unknown = prov("t", trial=True), prov("u", source="catalog", trial=None)
    db = make_db(bundled=[trial], catalog=[unknown])
    assert {p.id for p in db.filter(SearchQuery(require_trial=True))} == {"t", "u"}
    assert {p.id for p in db.filter(SearchQuery(require_trial=True, strict_flags=True))} == {"t"}


def test_vps_false_is_never_offered_and_catalog_toggles():
    sells = prov("sells", vps=True)
    no_vps = prov("novps", vps=False)
    confirmed = prov("conf", source="catalog", vps=True)
    unverified = prov("unv", source="catalog", vps=None)
    db = make_db(bundled=[sells, no_vps], catalog=[confirmed, unverified])
    assert {p.id for p in db.filter(SearchQuery())} == {"sells", "conf", "unv"}
    assert {p.id for p in db.filter(SearchQuery(include_unverified=False))} == {"sells", "conf"}
    assert {p.id for p in db.filter(SearchQuery(use_catalog=False))} == {"sells"}


def test_country_filter_uses_server_locations_not_headquarters():
    # штаб-квартира в Швеции, но серверы только в Финляндии — в шведской выдаче его быть не должно
    p = prov("fi-only", ["FI"], hq_country="SE")
    db = make_db(bundled=[p, prov("se-host", ["SE"])])
    assert {x.id for x in db.filter(SearchQuery(countries=["SE"]))} == {"se-host"}
    assert {x.id for x in db.filter(SearchQuery(countries=["FI"]))} == {"fi-only"}
    assert p.location_countries == ["FI"] and "SE" in p.countries  # .countries по-прежнему учитывает HQ


def test_location_countries_falls_back_to_hq_when_no_locations():
    assert Provider(id="x", name="X", hq_country="NO", locations=[]).location_countries == ["NO"]
    assert Provider(id="y", name="Y", locations=[]).location_countries == []


def test_ru_ties_and_size_filters():
    db = make_db(bundled=[prov("ru", ru_ties=True), prov("big", size="hyperscale"), prov("ok")])
    assert {p.id for p in db.filter(SearchQuery())} == {"big", "ok"}
    assert {p.id for p in db.filter(SearchQuery(include_ru_ties=True))} == {"ru", "big", "ok"}
    assert {p.id for p in db.filter(SearchQuery(max_size="medium"))} == {"ok"}


def test_price_filter_keeps_unknown_prices():
    db = make_db(bundled=[prov("cheap", min_price_eur=3), prov("pricey", min_price_eur=30), prov("unknown")])
    assert {p.id for p in db.filter(SearchQuery(max_price_eur=5))} == {"cheap", "unknown"}


# ───────────────────────── статистика ─────────────────────────
def test_country_stats_counts_sources_and_local_operators():
    db = make_db(
        bundled=[prov("a", ["SE", "FI"]), prov("b", ["FI"], hq_country="FI")],
        catalog=[prov("c", ["SE"], source="catalog")],
    )
    stats = db.country_stats()
    assert stats["SE"] == {"all": 2, "curated": 1, "catalog": 1, "local": 2}
    assert stats["FI"] == {"all": 2, "curated": 2, "catalog": 0, "local": 1}


@pytest.mark.parametrize("flag", [True, False, None])
def test_hints_only_depends_on_source(flag):
    assert prov("x", source="catalog", hourly=flag).hints_only
    assert not prov("y", hourly=flag).hints_only
