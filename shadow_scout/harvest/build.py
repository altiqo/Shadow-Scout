"""Сборка каталога: кандидаты из PeeringDB → префиксы и размер → списки блокировок → проверка сайтов → Provider."""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shadow_scout.analysis.engine import Services
from shadow_scout.cache import DiskCache
from shadow_scout.harvest.catalog_io import CATALOG_FILE, read_catalog, user_catalog_file, write_catalog
from shadow_scout.harvest.classify import (
    DENY_TYPES,
    HOSTILE_COUNTRIES,
    OrgCandidate,
    candidate_decision,
    domain_from_email,
    has_host_keyword,
    ip_type_for,
    is_big_brand,
    is_denied,
    normalize_city,
    normalize_website,
    pick_display_name,
    popularity_for,
    ru_linked,
    site_key,
    size_class,
    slugify,
    website_plausible,
)
from shadow_scout.harvest.peeringdb_dump import PeeringDbDump, load_dump
from shadow_scout.harvest.webscan import WebScan, scan_many
from shadow_scout.models import Location, Provider
from shadow_scout.net.ipindex import ipv4_size
from shadow_scout.paths import DATA_DIR

# Юрисдикции-«витрины»: юрлицо там, а серверы обычно в другой стране — берём страны присутствия в ДЦ.
OFFSHORE_HQ = {"BZ", "SC", "VG", "KY", "PA", "MH", "WS", "VU", "AG", "BS", "BB", "MU", "BM", "AI", "LC", "KN", "TC"}
OVERRIDES_FILE = DATA_DIR / "catalog_overrides.yaml"

__all__ = [
    "CATALOG_FILE",
    "CatalogOverrides",
    "HarvestOptions",
    "HarvestResult",
    "build_candidates",
    "harvest",
    "read_catalog",
    "user_catalog_file",
    "write_catalog",
]


@dataclass
class CatalogOverrides:
    """Ручные правки автокаталога, применяются при каждой сборке (data/catalog_overrides.yaml)."""

    deny_asns: set[int] = field(default_factory=set)
    force_asns: set[int] = field(default_factory=set)
    ru_asns: set[int] = field(default_factory=set)
    names: dict[int, str] = field(default_factory=dict)
    locations: dict[int, list[dict[str, str]]] = field(default_factory=dict)
    popularity: dict[int, int] = field(default_factory=dict)  # ASN → 1..5: известность в русскоязычном VPN-сообществе

    @classmethod
    def load(cls, path: Path | None = None) -> CatalogOverrides:
        path = path or OVERRIDES_FILE
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            deny_asns={int(x) for x in raw.get("deny_asns") or []},
            force_asns={int(x) for x in raw.get("force_asns") or []},
            ru_asns={int(x) for x in raw.get("ru_asns") or []},
            names={int(k): str(v) for k, v in (raw.get("names") or {}).items()},
            locations={int(k): list(v) for k, v in (raw.get("locations") or {}).items()},
            popularity={int(k): max(1, min(5, int(v))) for k, v in (raw.get("popularity") or {}).items()},
        )


@dataclass
class HarvestOptions:
    countries: list[str] = field(default_factory=list)  # пусто — все страны таблицы, кроме враждебных юрисдикций
    web_scan: bool = True
    check_blocklists: bool = True
    min_ipv4: int = 256
    max_ipv4: int = 1_048_576
    max_asns: int = 3
    max_locations: int = 6
    exclude_asns: set[int] = field(default_factory=set)  # уже есть в ручной базе
    exclude_ids: set[str] = field(default_factory=set)
    exclude_domains: set[str] = field(default_factory=set)
    overrides: CatalogOverrides = field(default_factory=CatalogOverrides)
    web_concurrency: int = 24
    prefix_concurrency: int = 16
    force_dump: bool = False
    hard_blocked_share: float = 0.5
    web_cache: Any = None  # DiskCache для результатов проверки сайтов (по умолчанию общий кеш приложения)
    dump_cache: Any = None  # FileCache для выгрузки PeeringDB


@dataclass
class HarvestResult:
    providers: list[Provider] = field(default_factory=list)
    stats: Counter = field(default_factory=Counter)
    dropped: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    def drop(self, reason: str, label: str) -> None:
        self.stats[f"drop:{reason}"] += 1
        if len(self.dropped[reason]) < 500:
            self.dropped[reason].append(label)


@dataclass
class _AsnData:
    asn: int
    ipv4: int
    blocked_share: float = 0.0


def build_candidates(dump: PeeringDbDump, include: set[str], max_locations: int = 6, known: set[str] | None = None) -> list[OrgCandidate]:
    """Организации PeeringDB из нужных стран с их сетями и локациями (по присутствию в ДЦ).

    known — страны, которые можно указывать в локациях (по умолчанию include): страны вне таблицы не показал бы мастер.
    """
    known = known if known is not None else include
    nets_by_org: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for net in dump.nets:
        if (net.get("info_type") or "") in DENY_TYPES:
            continue
        nets_by_org[net["org_id"]].append(net)
    facilities = dump.facilities_by_net()
    out: list[OrgCandidate] = []
    for org_id, nets in nets_by_org.items():
        org = dump.orgs.get(org_id)
        if not org:
            continue
        country = (org.get("country") or "").upper()
        if country not in include:
            continue
        website = org.get("website") or next((n.get("website") for n in nets if n.get("website")), None)
        cand = OrgCandidate(
            org_id=org_id,
            org_name=(org.get("name") or "").strip(),
            country=country,
            city=normalize_city(org.get("city")),
            website=normalize_website(website),
            nets=sorted(nets, key=lambda n: n["asn"]),
        )
        cand.locations = _locations(cand, facilities, max_locations, known)
        out.append(cand)
    return out


def build_name_candidates(records: Iterable[Any], include: set[str], covered_asns: set[int]) -> list[OrgCandidate]:
    """Кандидаты по именам ASN (ipverse): сети с признаками хостинга в названии, которых нет в PeeringDB.

    Один владелец (одинаковое описание в одной стране) — одна организация с несколькими ASN.
    """
    groups: dict[tuple[str, str], OrgCandidate] = {}
    for rec in records:
        if rec.asn in covered_asns or rec.country not in include:
            continue
        text = f"{rec.handle} {rec.description}"
        if not has_host_keyword(text) or is_denied(rec.description) or is_big_brand(text):
            continue
        key = (rec.country, rec.description.strip().lower())
        net = {"asn": rec.asn, "id": None, "name": rec.handle, "aka": None, "info_type": None, "info_prefixes4": None}
        cand = groups.get(key)
        if cand is None:
            groups[key] = OrgCandidate(
                org_id=-rec.asn, org_name=rec.description.strip(), country=rec.country, city=None, website=None,
                nets=[net], locations=[(rec.country, None)], origin="asn-name",
            )
        else:
            cand.nets.append(net)
    return list(groups.values())


def _locations(cand: OrgCandidate, facilities: dict[int, list[dict[str, Any]]], limit: int, known: set[str]) -> list[tuple[str, str | None]]:
    """Где можно арендовать сервер: дома (страна HQ) по присутствию в ДЦ, иначе там, где реально стоит оборудование.

    Присутствие в зарубежных ДЦ намеренно не добавляется к «домашним» — это чаще точки пиринга, а не VPS-узлы, и
    иначе один и тот же хостер всплывал бы в чужих странах.
    """
    counts: Counter[tuple[str, str | None]] = Counter()
    for net in cand.nets:
        for row in facilities.get(net.get("id"), []):
            cc = (row.get("country") or "").upper()
            if cc and cc not in HOSTILE_COUNTRIES and (cc in known or cc == cand.country):
                counts[(cc, normalize_city(row.get("city")))] += 1
    home = [key for key, _ in counts.most_common() if key[0] == cand.country]
    foreign = [key for key, _ in counts.most_common() if key[0] != cand.country]
    if cand.country in OFFSHORE_HQ and foreign:
        chosen = foreign
    elif home:
        chosen = home
    elif foreign:
        chosen = foreign[:3]  # юрлицо в одной стране, оборудование в другой
    else:
        return [(cand.country, cand.city)]
    result = list(dict.fromkeys(chosen))
    with_city = {cc for cc, city in result if city}  # «страна без города» лишняя, если есть конкретные города
    result = [(cc, city) for cc, city in result if city or cc not in with_city]
    return result[:limit]


async def _resolve_prefixes(
    services: Services, asns: list[int], concurrency: int, log: Callable[[str], None] | None
) -> dict[int, list[str]]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    out: dict[int, list[str]] = {}
    done = 0

    async def worker(asn: int) -> None:
        nonlocal done
        async with semaphore:
            try:
                prefixes, _ = await services.prefixes.prefixes(asn, prefer="ipverse")
            except Exception:  # noqa: BLE001 — недоступный ASN просто выпадает из каталога
                prefixes = []
            out[asn] = [p for p in prefixes if ":" not in p]
            done += 1
            if log and done % 250 == 0:
                log(f"Префиксы: {done}/{len(asns)} ASN")

    await asyncio.gather(*(worker(a) for a in asns))
    return out


async def _resolve_websites(services: Services, pending: list[tuple[OrgCandidate, int]], concurrency: int = 8) -> None:
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(cand: OrgCandidate, asn: int) -> None:
        async with semaphore:
            try:
                contacts = await services.ripe.abuse_contacts(asn)
            except Exception:  # noqa: BLE001
                return
        for email in contacts:
            domain = domain_from_email(email)
            if domain:
                cand.website = f"https://{domain}"
                return

    await asyncio.gather(*(worker(c, a) for c, a in pending))


def _asn_data(prefixes: dict[int, list[str]], bundle) -> dict[int, _AsnData]:
    data: dict[int, _AsnData] = {}
    for asn, plist in prefixes.items():
        total = sum(ipv4_size(p) for p in plist)
        blocked = 0
        if bundle is not None and bundle.ok_lists:
            for prefix in plist:
                b, _size, _hits = bundle.blocked_overlap(prefix)
                blocked += b
        data[asn] = _AsnData(asn, total, (blocked / total) if total else 0.0)
    return data


def _describe(scan: WebScan | None, types: list[str]) -> str:
    bits = ["Автокаталог: найден в PeeringDB" + (f" ({', '.join(types)})" if types else "")]
    if scan is None or (not scan.fetched and not scan.error):
        bits.append("сайт не проверялся")
    elif scan.vps:
        bits.append("на сайте есть VPS/облачные серверы")
    elif scan.fetched and scan.hosting:
        bits.append("на сайте хостинг/серверы, VPS не найден")
    elif scan.fetched:
        bits.append("на сайте признаков хостинга не найдено (возможно, страница строится скриптами)")
    else:
        bits.append("сайт не открылся")
    return "; ".join(bits) + ". Условия аренды (trial, цена, оплата) не проверены — смотрите сайт."


def make_provider(
    cand: OrgCandidate,
    chosen: list[_AsnData],
    scan: WebScan | None,
    overrides: CatalogOverrides,
    taken_ids: set[str],
) -> Provider:
    size = size_class(sum(a.ipv4 for a in chosen))
    name = next((overrides.names[a.asn] for a in chosen if a.asn in overrides.names), None) or pick_display_name(cand)
    slug = slugify(name)
    pid = slug if slug not in taken_ids else f"{slug}-as{chosen[0].asn}"
    taken_ids.add(pid)
    vps = True if scan and scan.vps else None
    types = cand.pdb_types
    ru = (
        any(a.asn in overrides.ru_asns for a in chosen)
        or ru_linked(f"{cand.org_name} {name}", cand.website, cand.country)
        or bool(scan and scan.russian)
    )
    state = "vps" if vps else ("hosting" if scan and scan.fetched and scan.hosting else "unverified")
    tags = ["catalog", state] + (["local"] if size in ("micro", "small") else []) + (["ru-linked"] if ru else [])
    locations = [Location(country=cc, city=city) for cc, city in cand.locations] or [Location(country=cand.country)]
    for item in chosen:
        if item.asn in overrides.locations:
            locations = [Location(country=loc["country"], city=loc.get("city")) for loc in overrides.locations[item.asn]]
            break
    best_net = max(cand.nets, key=lambda n: n.get("info_prefixes4") or 0)
    popularity = max((overrides.popularity[a.asn] for a in chosen if a.asn in overrides.popularity), default=popularity_for(size))
    return Provider(
        id=pid,
        name=name,
        website=cand.website,
        asns=[a.asn for a in chosen],
        hq_country=cand.country,
        locations=locations,
        size=size,
        popularity_ru=popularity,
        ip_type=ip_type_for(types),
        trial=None,
        hourly=True if (scan and scan.vps and scan.hourly) else None,
        ru_ties=ru,
        notes=_describe(scan, types),
        tags=tags,
        source="catalog",
        vps=vps,
        pdb_types=types,
        pdb_traffic=best_net.get("info_traffic") or None,
    )


async def harvest(
    services: Services,
    options: HarvestOptions,
    *,
    log: Callable[[str], None] | None = None,
    web_progress: Callable[[int, int], None] | None = None,
    transport: Any = None,
) -> HarvestResult:
    from shadow_scout.providers import load_countries

    result = HarvestResult()
    say = log or (lambda _m: None)
    table = load_countries()
    include = {c.upper() for c in options.countries} if options.countries else {code for code, c in table.countries.items() if c.radar != "hostile"}
    include -= HOSTILE_COUNTRIES
    ov = options.overrides

    dump = await load_dump(services.settings, services.http, cache=options.dump_cache, force=options.force_dump, log=say)
    candidates = build_candidates(dump, include, options.max_locations, known=set(table.countries))
    pdb_count = len(candidates)
    try:
        names_table = await services.asn_names.load(force=options.force_dump)
    except Exception as exc:  # noqa: BLE001 — таблица имён вторична; без неё остаётся PeeringDB
        say(f"Таблица имён ASN недоступна ({exc}) — только PeeringDB")
        names_table = {}
    candidates += build_name_candidates(names_table.values(), include, {n["asn"] for n in dump.nets} | options.exclude_asns)
    result.stats["orgs_in_countries"] = pdb_count
    result.stats["asn_name_candidates"] = len(candidates) - pdb_count

    # 1. правила по названию и типу сети
    kept: list[tuple[OrgCandidate, str]] = []
    for cand in candidates:
        asns = {n["asn"] for n in cand.nets}
        if asns & ov.deny_asns:
            result.drop("override", cand.org_name)
        elif asns & options.exclude_asns or site_key(cand.website) in options.exclude_domains:
            result.drop("already_in_curated", cand.org_name)
        elif asns & ov.force_asns:
            kept.append((cand, "keep"))
        elif (decision := candidate_decision(cand)) == "deny":
            result.drop("rules", cand.org_name)
        else:
            kept.append((cand, decision))
    say(f"После правил: {len(kept)} организаций (из {len(candidates)})")

    # 2. префиксы → размер → доля заблокированного
    all_asns = sorted({n["asn"] for cand, _ in kept for n in cand.nets})
    say(f"Загрузка префиксов для {len(all_asns)} ASN…")
    await services.http.start()
    prefixes = await _resolve_prefixes(services, all_asns, options.prefix_concurrency, say)
    bundle = await services.ensure_blocklists() if options.check_blocklists else None
    asn_data = _asn_data(prefixes, bundle)

    sized: list[tuple[OrgCandidate, str, list[_AsnData], bool]] = []
    for cand, decision in kept:
        forced = bool({n["asn"] for n in cand.nets} & ov.force_asns)
        live = sorted((asn_data[n["asn"]] for n in cand.nets if asn_data.get(n["asn"]) and asn_data[n["asn"]].ipv4 > 0), key=lambda a: -a.ipv4)
        if not live:
            result.drop("not_announced", cand.org_name)
            continue
        chosen = live[: options.max_asns]
        total = sum(a.ipv4 for a in chosen)
        blocked = sum(a.blocked_share * a.ipv4 for a in chosen) / total
        if not forced and total < options.min_ipv4:
            result.drop("too_small", cand.org_name)
        elif not forced and total > options.max_ipv4:
            result.drop("too_large", cand.org_name)
        elif not forced and blocked >= options.hard_blocked_share:
            result.drop("blocked", f"{cand.org_name} ({blocked:.0%})")
        else:
            sized.append((cand, decision, chosen, forced))
    say(f"После фильтра размера и блокировок: {len(sized)} организаций")

    # 3. сайты: для сетей, найденных только по имени ASN, домен берём из abuse-контакта
    pending = [(c, chosen[0].asn) for c, _, chosen, _ in sized if c.origin == "asn-name" and not c.website]
    if pending and options.web_scan:
        say(f"Поиск сайтов по abuse-контактам: {len(pending)}…")
        await _resolve_websites(services, pending)
        known = [t for t in sized if site_key(t[0].website) not in options.exclude_domains]
        for cand, *_ in sized:
            if site_key(cand.website) in options.exclude_domains and cand.origin == "asn-name":
                result.drop("already_in_curated", cand.org_name)
        sized = known
    scans: dict[str, WebScan] = {}
    if options.web_scan:
        sites = {str(c.org_id): c.website for c, _, _, _ in sized if c.website}
        say(f"Проверка сайтов: {len(sites)}…")
        scans = await scan_many(
            sites,
            concurrency=options.web_concurrency,
            proxy=services.settings.network.proxy,
            user_agent=services.settings.network.user_agent,
            cache=options.web_cache or DiskCache("webscan"),
            progress=web_progress,
            transport=transport,
        )

    # 4. итоговые решения и сборка Provider
    taken = set(options.exclude_ids)
    seen_sites: set[tuple[str, str]] = set()  # (домен, страна): одна компания не должна попасть в каталог дважды
    for cand, decision, chosen, forced in sorted(sized, key=lambda t: (t[0].country, t[0].org_name.lower())):
        scan = scans.get(str(cand.org_id))
        key = (site_key(cand.website), cand.country)
        if not forced and not cand.website:
            result.drop("no_website", cand.org_name)  # без сайта арендовать нечего и проверить нечем
            continue
        if key[0] and key in seen_sites:
            result.drop("duplicate_site", f"{cand.org_name} ({cand.website})")
            continue
        if not forced:
            handles = " ".join(n["name"] for n in cand.nets)
            if scan is not None and scan.fetched:
                if not (scan.vps or scan.hosting) and not (decision == "keep" and cand.strong_keyword):
                    # сайт открылся, но признаков хостинга нет, а в названии нет сильного слова (host/server/vps…)
                    result.drop("not_hosting", f"{cand.org_name} ({cand.website})")
                    continue
                if cand.origin == "asn-name" and not website_plausible(cand.org_name, handles, cand.website, scan.title):
                    result.drop("website_mismatch", f"{cand.org_name} ({cand.website})")
                    continue
            elif decision != "keep" or not cand.strong_keyword or (cand.origin == "asn-name" and not website_plausible(cand.org_name, handles, cand.website)):
                # сайт не открылся/не указан: верим только сильному признаку хостинга в названии (host/server/vps…, но не просто
                # «cloud»); для найденных по имени ASN — ещё и правдоподобию домена (он угадан по abuse-адресу)
                result.drop("no_site_evidence", cand.org_name)
                continue
        provider = make_provider(cand, chosen, scan, ov, taken)
        seen_sites.add(key)
        result.providers.append(provider)
        result.stats["vps_confirmed" if provider.vps else "not_confirmed"] += 1
    result.stats["providers"] = len(result.providers)
    return result
