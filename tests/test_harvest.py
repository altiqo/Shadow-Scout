"""Сбор каталога: правила классификации, разбор сайтов и сквозной прогон на синтетической выгрузке PeeringDB."""

from __future__ import annotations

import httpx
import pytest
from conftest import site_handler

from shadow_scout.cache import DiskCache, FileCache
from shadow_scout.harvest import classify
from shadow_scout.harvest.build import HarvestOptions, build_candidates, harvest
from shadow_scout.harvest.catalog_io import read_catalog, write_catalog
from shadow_scout.harvest.peeringdb_dump import PeeringDbDump
from shadow_scout.harvest.webscan import WebScan, analyze_html, scan_many
from shadow_scout.models import Provider


# ───────────────────────── классификация ─────────────────────────
@pytest.mark.parametrize(
    "text",
    ["Nordic VPS", "Blacknight Web Hosting", "CloudSigma", "Servers.com", "Datacenter Light", "Serverius colocation", "Tárhely.Eu", "Palvelinpuisto"],
)
def test_host_keywords_match(text):
    assert classify.has_host_keyword(text)


@pytest.mark.parametrize("text", ["Quiet Media", "Colombia Telecom", "Raidió Teilifís Éireann", "Acme Bank"])
def test_host_keywords_do_not_match_ordinary_names(text):
    assert not classify.has_host_keyword(text)


@pytest.mark.parametrize("name", ["AMS-IX Exchange", "Universität Wien", "Vodafone Czech", "Mullvad VPN", "Akamai Technologies", "StormWall"])
def test_denied_names(name):
    assert classify.is_denied(name)


def test_big_brands_are_not_cataloged():
    assert classify.is_big_brand("Hetzner Online GmbH")
    assert classify.is_big_brand("whatever", "www.ovh.net")
    assert not classify.is_big_brand("Nordic VPS")


@pytest.mark.parametrize(
    ("name", "website", "country", "expected"),
    [
        ("Aeza International", "https://aeza.net", "NL", True),
        ("Timeweb", "https://timeweb.cloud", "RU", True),
        ("Neutral Hosting", "https://neutral.ru", "NL", True),  # .ru-домен
        ("Хостинг Плюс", None, "NL", True),  # кириллица
        ("Nordic VPS", "https://nordicvps.se", "SE", False),
    ],
)
def test_ru_linked(name, website, country, expected):
    assert classify.ru_linked(name, website, country) is expected


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("Blacknight Internet Solutions Ltd", "Blacknight Internet Solutions"),
        ("MAXKO d.o.o.", "MAXKO"),
        ("Edge Hosting s.r.o.", "Edge Hosting"),
        ("Gigahost AS", "Gigahost"),
        ("SIA RixHost", "RixHost"),
        ("Foo Hosting GmbH & Co. KG", "Foo Hosting"),
        ("Nordic VPS AB", "Nordic VPS"),
        ("Webtasy", "Webtasy"),
    ],
)
def test_clean_name(raw, clean):
    assert classify.clean_name(raw) == clean


def test_slug_city_size_helpers():
    assert classify.slugify("Tárhely.Eu Kft.") == "tarhely-eu-kft"
    assert classify.slugify("***") == "provider"
    assert classify.normalize_city("STOCKHOLM") == "Stockholm"
    assert classify.normalize_city("Frankfurt (Main)") == "Frankfurt"
    assert classify.normalize_city("  ") is None and classify.normalize_city("12345 Foo Street 7") is None
    assert [classify.size_class(n) for n in (256, 4096, 4097, 32768, 262144, 262145, 2_000_000)] == ["micro", "micro", "small", "small", "medium", "large", "hyperscale"]
    assert classify.website_domain("HTTPS://www.Example.com/path?x=1") == "example.com"
    assert classify.website_domain("not a url") is None
    assert classify.domain_from_email("abuse@Nordic.example") == "nordic.example"
    assert classify.domain_from_email("john@gmail.com") is None and classify.domain_from_email("abuse@hetzner.com") is None


@pytest.mark.parametrize(
    ("org", "handle", "site", "title", "ok"),
    [
        ("SIA EasyHost", "EASYHOST-AS", "https://easyhost.example", None, True),
        ("Gigahost AS", "FSIX-AS", "https://as56655.net", None, False),  # abuse-адрес апстрима, не самого провайдера
        ("Boldhost SIA", "BOLDHOST-AS", "https://matul.net", "Matul — web agency", False),
        ("Cloud Center Finland Oy", "CLOUDCENTER", "https://pilvikeskus.fi", "Cloud Center Finland", True),  # совпал заголовок страницы
        ("Nordic Servers AS", "NORDIC-SERVERS", "https://nordicservers.no", None, True),
        ("Hosting Ltd", "HOSTING-AS", "https://anything.example", None, True),  # только общие слова — сверять не с чем
        ("RixHost", "RIXHOST", None, None, False),
        ("Datacenter d.o.o.", "MARC-NET-AS", "https://datacenter.si", None, True),  # название целиком совпало с доменом
        ("SAMPLING LINE-SERVICOS E INTERNET, LDA", "SAMPLING", "https://www.ptservidor.pt", None, False),  # другой бренд
    ],
)
def test_website_plausibility_for_asn_name_candidates(org, handle, site, title, ok):
    assert classify.website_plausible(org, handle, site, title) is ok


async def test_harvest_drops_asn_name_candidates_whose_website_is_not_theirs(services, tmp_path, monkeypatch):
    """Сайт, угаданный по abuse-адресу, должен быть похож на название организации — иначе пользователь пойдёт не туда."""
    from shadow_scout.net.ripestat import RipeStatClient

    async def foreign_abuse(self, asn):
        return ["abuse@nordicvps.example"]  # домен чужого провайдера

    monkeypatch.setattr(RipeStatClient, "abuse_contacts", foreign_abuse)
    result = await run_harvest(services, tmp_path)
    assert 64605 not in {a for p in result.providers for a in p.asns}
    assert any("EasyHost" in label for label in result.dropped["website_mismatch"])


def test_site_key_is_registrable_domain():
    assert classify.site_key("https://staff.aruba.it/x") == "aruba.it" and classify.site_key("https://www.hostco.co.uk") == "hostco.co.uk"
    assert classify.site_key(None) == ""


async def test_harvest_excludes_entries_on_subdomains_of_known_sites(services, tmp_path):
    result = await run_harvest(services, tmp_path, exclude_domains={"nordicvps.example"})
    assert 64601 not in {a for p in result.providers for a in p.asns}


def test_site_stem_ignores_subdomains_and_zone():
    assert classify.site_stem("https://cloud.orange-business.com/x") == "orange-business"
    assert classify.site_stem("https://www.hostco.co.uk") == "hostco"
    assert classify.site_stem("nordicvps.se") == "nordicvps"
    assert classify.site_stem(None) == "" and classify.site_stem("not a url") == ""


def test_subdomain_does_not_make_a_big_company_a_hoster():
    cand = classify.OrgCandidate(org_id=1, org_name="Orange Business Services", country="NO", city=None, website="https://cloud.orange-business.com",
                                 nets=[{"asn": 1, "name": "Orange Business Services", "info_types": ["Content"]}])
    assert not cand.keyword and classify.candidate_decision(cand) == "deny"  # Orange — оператор связи, а не VPS-хостер


def test_strong_keywords_are_stricter_than_cloud():
    assert classify.has_strong_host_keyword("Host Europe GmbH") and classify.has_strong_host_keyword("ServerZone s.r.o.")
    assert classify.has_strong_host_keyword("ptservidor") and classify.has_strong_host_keyword("Szerverplex") and classify.has_strong_host_keyword("Alojamiento Web")
    assert not classify.has_strong_host_keyword("CloudNow GmbH") and not classify.has_strong_host_keyword("Cloud Terra Pty Ltd")


def test_not_a_hoster_filter_is_lifted_only_by_strong_keywords():
    def cand(name, site="https://x.example"):
        return classify.OrgCandidate(org_id=1, org_name=name, country="US", city=None, website=site, nets=[{"asn": 1, "name": name, "info_types": ["Content"]}])

    assert classify.candidate_decision(cand("CITY OF ST. CLOUD")) == "deny"  # «cloud» — не признак хостинга
    assert classify.candidate_decision(cand("Holzer Health System")) == "deny"
    assert classify.candidate_decision(cand("Mounds View Public Schools")) == "deny"
    assert classify.candidate_decision(cand("Fidelity National Financial")) == "deny"
    assert classify.candidate_decision(cand("Health Hosting Ltd")) == "keep"  # «Hosting» — сильный признак
    assert classify.candidate_decision(cand("Cloud Terra", None)) == "keep"  # слабый признак, но не «запрещённое» название — решит сайт


def test_candidate_decision():
    def cand(name, types, site="https://x.example"):
        return classify.OrgCandidate(org_id=1, org_name=name, country="SE", city=None, website=site, nets=[{"asn": 1, "name": name, "info_types": types}])

    assert classify.candidate_decision(cand("Nordic VPS", ["Content"])) == "keep"
    assert classify.candidate_decision(cand("Quiet Media", ["Content"])) == "maybe"  # нужна проверка сайта
    assert classify.candidate_decision(cand("Quiet Media", ["Cable/DSL/ISP"])) == "deny"
    assert classify.candidate_decision(cand("Some IX", ["Route Server"])) == "deny"
    assert classify.candidate_decision(cand("Hetzner Online", ["Content"])) == "deny"
    assert classify.candidate_decision(cand("Telekom Hosting Services", ["NSP"])) == "keep"  # явный признак хостинга важнее «telekom»


# ───────────────────────── разбор сайтов ─────────────────────────
def test_analyze_html_detects_vps_and_hourly():
    page = analyze_html("<html lang='en'><head><title>Acme  Cloud</title></head><body>Cheap <b>VPS</b> servers — from $3 per hour.<script>var vps=1</script></body></html>")
    assert page.vps and page.hosting and page.hourly and page.lang == "en" and page.title == "Acme Cloud"
    assert not analyze_html("<body>Film production company. Contact us.</body>").hosting


@pytest.mark.parametrize(
    "text",
    ["Virtuális szerver bérlés", "Virtueller Server mieten", "Serveur virtuel pas cher", "Servidor virtual en España", "serwer VPS od 9 zł", "Виртуальный сервер от 99 руб", "Virtuaalserver kuus"],
)
def test_analyze_html_vps_in_other_languages(text):
    assert analyze_html(f"<body><p>{text}</p></body>").vps


@pytest.mark.parametrize(
    "text",
    [
        "Hourly billing and monthly billing", "You pay per hour, no commitment", "Billed by the hour", "from 0.01 EUR/hour", "Preise pro Stunde",
        "ingen bindningstid du betalar per timme", "óradíjas elszámolás a felhő szolgáltatásban", "Оплата за час использования", "tuntilaskutus ilman sitoutumista",
    ],
)
def test_hourly_detection_positive(text):
    assert analyze_html(f"<body>{text}</body>").hourly


@pytest.mark.parametrize(
    "text",
    [
        "it takes no more than half an hour", "kaksivaiheisen tunnistautumisen asetus", "stündliches Backup, bis zu 180 Tage", "hourly backups included",
        "külön óradíj fejében támogatás", "open 24 hours a day", "after-hours support",
    ],
)
def test_hourly_detection_ignores_lookalikes(text):
    assert not analyze_html(f"<body>{text}</body>").hourly


def test_hourly_evidence_is_captured_for_review():
    page = analyze_html("<body>Cloud VPS plans. Billed hourly or monthly, you choose.</body>")
    assert "billed hourly" in page.hourly_evidence


def test_analyze_html_hosting_without_vps():
    page = analyze_html("<body>Webhosting, domains and colocation in Prague</body>")
    assert page.hosting and not page.vps


def test_analyze_html_finds_subpages_on_same_site_only():
    html = (
        "<a href='/vps-hosting'>VPS</a><a href='/about'>About</a><a href='https://other.example/vps'>Partner</a>"
        "<a href='/cloud/servers?x=1'>Cloud servers</a><a href='mailto:a@b.c'>mail</a><a href='/pricing.pdf'>PDF</a>"
    )
    links = analyze_html(f"<body>{html}</body>", "https://host.example/").links
    assert links == ["https://host.example/vps-hosting", "https://host.example/cloud/servers"]


def test_analyze_html_distinguishes_russian_from_other_cyrillic_languages():
    russian = analyze_html("<body>Хостинг и аренда серверов для вашего бизнеса. Звоните нам сегодня, мы всегда рады помочь.</body>")
    assert russian.cyrillic and russian.russian
    bulgarian = analyze_html("<body>Уеб хостинг и виртуални сървъри за вашия бизнес. Свържете се с нас днес, за да получите оферта.</body>")
    assert bulgarian.cyrillic and not bulgarian.russian  # кириллица, но не русский: болгарские хостеры не «связаны с РФ»
    assert not analyze_html("<body>Hosting and servers</body>").cyrillic


async def test_scan_many_follows_pricing_subpage_for_hourly(tmp_path):
    pages = {
        "/": "<body>VPS hosting <a href='/pricing'>Pricing</a></body>",
        "/pricing": "<body>Plans start at 3 EUR per hour</body>",
    }
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        body = pages.get(request.url.path)
        return httpx.Response(200, text=body) if body else httpx.Response(404)

    cache = DiskCache("webscan", tmp_path)
    scans = await scan_many({"a": "https://site.example"}, transport=httpx.MockTransport(handler), cache=cache)
    assert scans["a"].vps and scans["a"].hourly and scans["a"].pages == 2
    # повторный прогон берёт результат из кеша и не ходит в сеть
    seen.clear()
    again = await scan_many({"a": "https://site.example"}, transport=httpx.MockTransport(handler), cache=cache)
    assert again["a"].vps and not seen


async def test_scan_many_handles_missing_and_dead_sites():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    scans = await scan_many({"dead": "https://dead.example", "none": ""}, transport=httpx.MockTransport(handler))
    assert not scans["dead"].fetched and scans["dead"].error == "сайт недоступен"
    assert scans["none"].error == "нет сайта"


# ───────────────────────── кандидаты и локации ─────────────────────────
def dump_from_fixtures() -> PeeringDbDump:
    import conftest

    return PeeringDbDump(nets=conftest.PDB_DUMP_NETS, orgs={o["id"]: o for o in conftest.PDB_DUMP_ORGS}, netfacs=conftest.PDB_DUMP_NETFAC)


def test_candidate_locations_home_only_foreign_peering_ignored():
    cands = {c.org_name: c for c in build_candidates(dump_from_fixtures(), {"SE", "CZ", "BZ", "HR"}, known={"SE", "CZ", "BZ", "HR", "NL", "DE"})}
    # Nordic VPS: дома Стокгольм, точка пиринга в Амстердаме не считается VPS-узлом
    assert cands["Nordic VPS AB"].locations == [("SE", "Stockholm")]
    # Edge Hosting: Прага дома, Франкфурт — чужая страна
    assert cands["Edge Hosting s.r.o."].locations == [("CZ", "Prague")]
    # оффшорное юрлицо (Белиз): реальное оборудование — там, где присутствие в ДЦ
    assert cands["Offshore Servers Ltd"].locations == [("NL", "Amsterdam")]
    # нет данных о ДЦ — адрес штаб-квартиры
    assert cands["Cloudy Balkans d.o.o."].locations == [("HR", "Zagreb")]
    assert "Some IX" not in cands  # единственная сеть организации — Route Server


def test_locations_only_in_countries_the_wizard_knows():
    """Страна оборудования вне таблицы стран не должна попадать в локации — мастер её не покажет."""
    dump = dump_from_fixtures()
    dump.netfacs = [*dump.netfacs, {"net_id": 8, "city": "Port of Spain", "country": "TT", "local_asn": 64604, "status": "ok"}]
    cands = {c.org_name: c for c in build_candidates(dump, {"NL"}, known={"NL", "SE"})}
    assert cands["Tiny Block Host"].locations == [("NL", "Amsterdam")]  # TT отброшено, остаётся штаб-квартира
    foreign_only = build_candidates(dump, {"NL"}, known={"NL"})
    assert all(cc == "NL" for c in foreign_only for cc, _city in c.locations)


def test_candidates_skip_deny_types_and_excluded_countries():
    cands = {c.org_name for c in build_candidates(dump_from_fixtures(), {"SE", "FI"})}
    assert "Some IX" not in cands  # единственная сеть — Route Server
    assert "Moskva Hosting" not in cands  # RU вне набора стран


# ───────────────────────── сквозной сбор ─────────────────────────
async def run_harvest(services, tmp_path, **kw):
    options = HarvestOptions(
        web_cache=DiskCache("webscan", tmp_path), dump_cache=FileCache("dump", tmp_path),
        countries=["SE", "FI", "HR", "BZ", "CZ", "NL", "DE", "LV"], **kw,
    )
    return await harvest(services, options, transport=httpx.MockTransport(site_handler))


async def test_harvest_end_to_end(services, tmp_path):
    result = await run_harvest(services, tmp_path)
    by_name = {p.name: p for p in result.providers}

    nordic = by_name["Nordic VPS"]
    assert nordic.asns == [64601] and nordic.hq_country == "SE" and nordic.source == "catalog"
    assert nordic.vps is True and nordic.hourly is True and nordic.trial is None  # trial не определяем автоматически
    assert [(loc.country, loc.city) for loc in nordic.locations] == [("SE", "Stockholm")]
    assert nordic.size == "micro" and nordic.popularity_ru == 1 and nordic.pdb_types == ["Content"]  # /23 = 512 адресов
    assert "catalog" in nordic.tags and "vps" in nordic.tags and not nordic.ru_ties

    # не хостинг (сайт открылся, признаков нет), большие бренды, враждебная страна, IX — отсеяны
    for gone in ("Quiet Media", "Hetzner Online", "Moskva Hosting", "Some IX Route Server"):
        assert gone not in by_name, gone
    assert "Quiet Media" in " ".join(result.dropped["not_hosting"])
    # сеть целиком в списках блокировок
    assert any("Tiny Block" in label for label in result.dropped["blocked"])

    # сайт не открылся, но в названии сильный признак («Hosty» ← host) — оставляем как неподтверждённого
    hosty = by_name["Hosty Balkans"]
    assert hosty.vps is None and "unverified" in hosty.tags
    # только «cloud» в названии — слабый признак: без подтверждения сайтом запись не берём
    assert "Cloudy Balkans" not in by_name and "Cloudy Balkans d.o.o." in result.dropped["no_site_evidence"]

    # оффшор: локация — страна оборудования; сайт без hourly → почасовая неизвестна
    assert [loc.country for loc in by_name["Offshore Servers"].locations] == ["NL"]
    assert by_name["Offshore Servers"].hourly is None
    # хостинг без VPS: тег hosting, vps не подтверждён
    edge = by_name["Edge Hosting"]
    assert edge.vps is None and "hosting" in edge.tags


async def test_harvest_finds_asn_only_hosters_via_abuse_contact(services, tmp_path):
    result = await run_harvest(services, tmp_path)
    easy = next(p for p in result.providers if p.asns == [64605])
    assert easy.name == "EasyHost" and easy.hq_country == "LV"  # «SIA» отброшено
    assert easy.website == "https://easyhost.example" and easy.vps is True and easy.hourly is True


async def test_harvest_respects_exclusions(services, tmp_path):
    result = await run_harvest(services, tmp_path, exclude_asns={64601}, exclude_domains={"easyhost.example"})
    assert 64601 not in {a for p in result.providers for a in p.asns}
    assert 64605 not in {a for p in result.providers for a in p.asns}
    assert "Nordic VPS AB" in result.dropped["already_in_curated"]


async def test_harvest_keeps_js_sites_with_strong_name_but_drops_vague_ones(services, tmp_path, monkeypatch):
    """Сайт открылся, а текста для распознавания нет (JS/антибот): «Host Europe» остаётся неподтверждённым, «CloudNow» — нет."""
    import conftest

    monkeypatch.setitem(conftest.SITES, "nordicvps.example", "<html><body><div id='app'></div></body></html>")
    monkeypatch.setitem(conftest.SITES, "cloudy.example", "<html><body><div id='app'></div></body></html>")
    result = await run_harvest(services, tmp_path)
    by_name = {p.name: p for p in result.providers}
    nordic = by_name["Nordic VPS"]  # в названии «vps» — сильный признак
    assert nordic.vps is None and "unverified" in nordic.tags and "скриптами" in nordic.notes
    assert "Cloudy Balkans" not in by_name  # только «cloud» — слабый признак, а сайт ничего не подтвердил
    assert any("Cloudy Balkans" in label for label in result.dropped["not_hosting"])


async def test_harvest_without_web_scan_keeps_only_name_evidence(services, tmp_path):
    result = await run_harvest(services, tmp_path, web_scan=False)
    names = {p.name for p in result.providers}
    assert "Nordic VPS" in names and "Hosty Balkans" in names  # в названии есть vps/host
    assert "Cloudy Balkans" not in names  # одно «cloud» без проверки сайта — слишком слабо
    assert "Quiet Media" not in names  # «Content» без признаков хостинга без проверки сайта не берём
    assert "EasyHost" not in names  # найденные по имени ASN без сайта подтвердить нельзя
    assert all(p.vps is None for p in result.providers)


async def test_harvest_skips_entries_without_website_and_duplicate_sites(services, tmp_path, monkeypatch):
    import conftest

    nets = conftest.PDB_DUMP_NETS + [
        conftest._net(20, 30, 64620, "Nordic VPS Norway", "Content", "https://nordicvps.example"),  # тот же сайт, другая организация
        conftest._net(21, 31, 64621, "Webless Hosting", "Content", ""),  # сайта нет
    ]
    orgs = conftest.PDB_DUMP_ORGS + [
        {"id": 30, "name": "Nordic VPS Norge AS", "aka": "", "country": "SE", "city": "Stockholm", "website": "https://nordicvps.example", "status": "ok"},
        {"id": 31, "name": "Webless Hosting", "aka": "", "country": "SE", "city": "Malmo", "website": "", "status": "ok"},
    ]
    conftest.ASN_DATA[64620] = {"holder": "NORDIC-NO", "prefixes": ["10.120.0.0/24"]}
    conftest.ASN_DATA[64621] = {"holder": "WEBLESS", "prefixes": ["10.121.0.0/24"]}
    monkeypatch.setattr(conftest, "PDB_DUMP_NETS", nets)
    monkeypatch.setattr(conftest, "PDB_DUMP_ORGS", orgs)
    try:
        result = await run_harvest(services, tmp_path)
    finally:
        conftest.ASN_DATA.pop(64620, None)
        conftest.ASN_DATA.pop(64621, None)
    asns = {a for p in result.providers for a in p.asns}
    assert 64601 in asns and 64620 not in asns and 64621 not in asns
    assert any("Webless" in label for label in result.dropped["no_website"])
    assert any("Nordic VPS Norge" in label for label in result.dropped["duplicate_site"])


async def test_harvest_force_and_deny_overrides(services, tmp_path):
    from shadow_scout.harvest.build import CatalogOverrides

    overrides = CatalogOverrides(deny_asns={64601}, force_asns={64602}, ru_asns={64608}, names={64608: "Hosty HR"})
    result = await run_harvest(services, tmp_path, overrides=overrides)
    by_asn = {a: p for p in result.providers for a in p.asns}
    assert 64601 not in by_asn
    assert 64602 in by_asn  # «Quiet Media» принудительно включён, хотя сайт не про хостинг
    assert by_asn[64608].name == "Hosty HR" and by_asn[64608].ru_ties


# ───────────────────────── запись/чтение каталога ─────────────────────────
def test_catalog_roundtrip(tmp_path):
    providers = [
        Provider(id="a", name="Äpfel Hosting", website="https://a.example", asns=[1, 2], hq_country="SE", source="catalog", vps=True, tags=["catalog"], notes="Заметка"),
        Provider(id="b", name="B", asns=[3], hq_country="FI", source="catalog"),
    ]
    path = write_catalog(providers, tmp_path / "c.json", sources=["test"])
    meta, items = read_catalog(path)
    assert meta["count"] == 2 and meta["sources"] == ["test"]
    assert items[0]["name"] == "Äpfel Hosting" and items[0]["asns"] == [1, 2] and "source" not in items[0]
    assert Provider.model_validate({**items[1], "source": "catalog"}).asns == [3]
    assert read_catalog(tmp_path / "missing.json") == ({}, [])
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    assert read_catalog(tmp_path / "broken.json") == ({}, [])


def test_webscan_roundtrip_dict():
    scan = WebScan(url="https://x", fetched=True, vps=True, hourly=True, lang="en")
    assert WebScan.from_dict({**scan.to_dict(), "unknown_field": 1}) == scan


async def test_harvest_popularity_override(services, tmp_path):
    from shadow_scout.harvest.build import CatalogOverrides

    result = await run_harvest(services, tmp_path, overrides=CatalogOverrides(popularity={64601: 5}))
    by_asn = {a: p for p in result.providers for a in p.asns}
    assert by_asn[64601].popularity_ru == 5  # известный в сообществе хостер, хоть сеть и маленькая
    assert by_asn[64605].popularity_ru == 1


def test_shipped_catalog_overrides_are_valid():
    """Файл ручных правок поставляется с программой — ошибка в нём сломала бы каждую пересборку каталога."""
    from shadow_scout.harvest.build import CatalogOverrides

    ov = CatalogOverrides.load()
    assert ov.deny_asns and not (ov.deny_asns & ov.force_asns)
    assert all(isinstance(a, int) and a > 0 for a in ov.deny_asns | ov.force_asns | ov.ru_asns | set(ov.names) | set(ov.popularity))
    assert all(1 <= v <= 5 for v in ov.popularity.values())
    assert all(isinstance(name, str) and name for name in ov.names.values())
