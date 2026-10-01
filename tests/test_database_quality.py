"""Качество поставляемых данных (ручная база + автокаталог): размер, покрытие локаций, корректность записей.

Это защита от регрессий главной проблемы: «2–3 варианта на локацию, везде один и тот же хостер». Пороги подобраны так,
чтобы их нарушение означало реальную деградацию базы, а не мелкую правку.
"""

from __future__ import annotations

import re
from collections import Counter

import pytest

from shadow_scout import selection
from shadow_scout.models import SearchQuery
from shadow_scout.providers import ProviderDB, load_countries

# страны, предвыбранные в мастере поиска («низкий радар»), кроме микрогосударств, где хостеров почти нет по определению
CORE_LOW_RADAR = ["SE", "FI", "NO", "DK", "IS", "EE", "LV", "LT", "HU", "CZ", "SK", "AT", "CH", "SI", "HR", "PT", "IE", "BE"]
# минимум провайдеров в локации при настройках мастера по умолчанию. Факт на момент сборки каталога (2026-10-01) — в комментарии;
# пороги ниже фактических с запасом на дрейф данных. Тонкие рынки (HR, IE, SI, IS) — это границы открытых данных, а не ошибка.
MIN_PER_COUNTRY = {
    "SE": 25,  # 36
    "CH": 25,  # 37
    "CZ": 20,  # 29
    "DK": 12,  # 19
    "AT": 12,  # 19
    "EE": 12,  # 17
    "FI": 10,  # 14
    "HU": 10,  # 15
    "NO": 8,  # 11
    "LV": 8,  # 11
    "LT": 7,  # 9
    "SK": 7,  # 10
    "BE": 7,  # 9
    "PT": 5,  # 7
    "IS": 4,  # 5
    "SI": 4,  # 5
    "IE": 3,  # 4
    "HR": 2,  # 2
}


@pytest.fixture(scope="module")
def db() -> ProviderDB:
    return ProviderDB()


@pytest.fixture(scope="module")
def default_query() -> SearchQuery:
    """Что реально видит пользователь мастера: без связей с РФ, без крупных хостингов."""
    return SearchQuery(max_size="medium", include_ru_ties=False)


# ───────────────────────── размер ─────────────────────────
def test_database_is_several_times_larger_than_before(db):
    providers = db.all(include_disabled=True)
    curated = [p for p in providers if p.source != "catalog"]
    catalog = [p for p in providers if p.source == "catalog"]
    assert len(curated) >= 100
    assert len(catalog) >= 1200
    assert len(providers) >= 1300  # было 144


def test_every_core_low_radar_country_has_enough_options(db, default_query):
    stats = db.country_stats(default_query)
    thin = {cc: stats.get(cc, {}).get("all", 0) for cc in CORE_LOW_RADAR if stats.get(cc, {}).get("all", 0) < MIN_PER_COUNTRY[cc]}
    assert not thin, f"мало провайдеров в локациях (страна: сколько): {thin}"


def test_local_operators_not_just_multinational_presence(db, default_query):
    """«Местные» (штаб-квартира в стране) — главное, чего не хватало: раньше в малых странах были одни мультилокационные хостеры."""
    stats = db.country_stats(default_query)
    few_local = {cc: stats.get(cc, {}).get("local", 0) for cc in CORE_LOW_RADAR if stats.get(cc, {}).get("local", 0) < max(2, MIN_PER_COUNTRY[cc] // 2)}
    assert not few_local, few_local


def test_multi_country_giants_do_not_dominate_any_core_location(db, default_query):
    """Доля «мульти-страновых» провайдеров (4+ страны) в локации не должна превращать выдачу в «везде один и тот же»."""
    for cc in CORE_LOW_RADAR:
        providers = [p for p in db.filter(default_query) if cc in p.location_countries]
        giants = [p for p in providers if len(p.location_countries) >= 4]
        assert len(giants) <= max(3, len(providers) * 0.3), (cc, [p.id for p in giants])


def test_default_plan_covers_every_core_location(db, default_query):
    """Основной сценарий: мастер по умолчанию (все страны «низкого радара», лимит по умолчанию) не оставляет ни одной локации пустой."""
    query = default_query.model_copy(update={"countries": load_countries().low_radar_codes()})
    plan = selection.plan_candidates(db.filter(query), query)
    covered = {cc for (cc, _city) in plan.groups}
    assert set(CORE_LOW_RADAR) <= covered
    per_location = Counter(loc.country for p in plan.candidates for loc in p.locations if loc.country in CORE_LOW_RADAR)
    # локация не «голодает»: в план попадает всё, что есть в базе, но не меньше «сколько показать» (там, где столько есть)
    starved = {cc: (per_location[cc], plan.groups[(cc, None)]) for cc in CORE_LOW_RADAR if per_location[cc] < min(query.per_location, plan.groups[(cc, None)])}
    assert not starved, starved
    assert len(plan.candidates) <= query.limit


# ───────────────────────── корректность записей ─────────────────────────
def test_ids_are_unique_and_asns_valid(db):
    providers = db.all(include_disabled=True)
    ids = [p.id for p in providers]
    assert len(ids) == len(set(ids))
    for p in providers:
        assert p.asns or p.asn_search, p.id
        assert all(isinstance(a, int) and 0 < a < 4_294_967_296 for a in p.asns), p.id


def test_no_asn_is_claimed_by_two_providers(db):
    owners: dict[int, list[str]] = {}
    for p in db.all(include_disabled=True):
        for asn in p.asns:
            owners.setdefault(asn, []).append(p.id)
    shared = {asn: ids for asn, ids in owners.items() if len(ids) > 1}
    # допустимы только осознанные пары в ручной базе (бренды одной сети); в автокаталоге дублей быть не должно
    catalog_dupes = {asn: ids for asn, ids in shared.items() if any(db.get(i).source == "catalog" for i in ids)}
    assert not catalog_dupes, catalog_dupes


def test_curated_providers_pin_exact_asns(db):
    """Поиск ASN по названию хрупок (в базе нашлись перепутанные ASN): в ручной базе ASN указаны явно."""
    search_only = [p.id for p in db.all(include_disabled=True) if p.source == "bundled" and not p.asns]
    assert not search_only, search_only


def test_countries_are_known_and_urls_well_formed(db):
    countries = load_countries().countries
    for p in db.all(include_disabled=True):
        assert p.hq_country in countries or p.hq_country == "ZZ", (p.id, p.hq_country)
        for loc in p.locations:
            assert loc.country in countries, (p.id, loc.country)
        if p.website:
            assert re.match(r"^https?://[^\s/]+\.[^\s/]+", p.website), (p.id, p.website)


def test_catalog_entries_are_well_formed(db):
    catalog = [p for p in db.all(include_disabled=True) if p.source == "catalog"]
    for p in catalog:
        assert p.asns, p.id
        assert p.locations, p.id
        assert p.trial is None, p.id  # trial автоматически не определяется
        assert p.vps in (True, None), p.id
        assert {"catalog"} <= set(p.tags) and set(p.tags) & {"vps", "hosting", "unverified"}, (p.id, p.tags)
        assert p.size in ("micro", "small", "medium", "large"), (p.id, p.size)  # гипермасштабные в каталог не берём
        assert (p.vps is True) == ("vps" in p.tags), (p.id, p.vps, p.tags)
    # у части записей сайт подтвердил VPS — иначе правила сбора ничего не фильтруют
    assert sum(1 for p in catalog if p.vps) >= 100


def test_catalog_does_not_leak_russian_ties_into_default_search(db, default_query):
    default = db.filter(default_query)
    assert not [p.id for p in default if p.ru_ties]
    ru_linked_ids = [p.id for p in db.all() if p.source == "catalog" and p.ru_ties]
    assert not (set(ru_linked_ids) & {p.id for p in default})


def test_catalog_has_no_hostile_jurisdictions(db):
    hostile = {code for code, c in load_countries().countries.items() if c.radar == "hostile"}
    leaked = [p.id for p in db.all(include_disabled=True) if p.source == "catalog" and p.hq_country in hostile]
    assert not leaked, leaked


def test_curated_records_are_confirmed_vps_sellers(db):
    for p in db.all(include_disabled=True):
        if p.source == "bundled":
            assert p.vps is True, p.id
            assert p.min_price_eur is None or p.min_price_eur >= 0, p.id
