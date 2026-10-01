"""Оркестратор: собирает данные по провайдеру из всех источников и строит RiskReport."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from shadow_scout import selection
from shadow_scout.analysis import signals as sig
from shadow_scout.analysis.scoring import score_report
from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.models import (
    AsnInfo,
    Location,
    Provider,
    RiskReport,
    SearchQuery,
    SearchResult,
    SourceStatus,
)
from shadow_scout.net.asnnames import AsnNameTable
from shadow_scout.net.blocklists import BlocklistBundle, BlocklistManager
from shadow_scout.net.cheburcheck import CheburcheckClient
from shadow_scout.net.doh import Resolver
from shadow_scout.net.http import HealthRegistry, HttpClient, HttpError
from shadow_scout.net.ipapi import IpApiClient
from shadow_scout.net.ipindex import ipv4_size, sample_ips
from shadow_scout.net.liveprobe import control_reachable, probe_many
from shadow_scout.net.peeringdb import PeeringDbClient
from shadow_scout.net.prefixes import PrefixResolver
from shadow_scout.net.ripestat import RipeStatClient
from shadow_scout.providers import CountryTable, load_countries

MAX_ASNS_PER_PROVIDER = 3
MAX_CHEBURCHECK_ASNS = 2
FULL_ANALYSIS_MAX = 12  # до такого числа провайдеров проверяем всех полностью, без двухфазной схемы
MAX_DEEP_ROUNDS = 4  # сколько раз повторять углубление, если лучшие на локацию после проверки «просели»

StageCallback = Callable[[Provider, str, str], None]
DoneCallback = Callable[[RiskReport], None]
LogCallback = Callable[[str], None]
PhaseCallback = Callable[[str, int], None]


@dataclass
class ProgressHooks:
    on_stage: StageCallback | None = None
    on_done: DoneCallback | None = None
    on_log: LogCallback | None = None
    on_phase: PhaseCallback | None = None

    def stage(self, provider: Provider, stage: str, message: str = "") -> None:
        if self.on_stage:
            self.on_stage(provider, stage, message)

    def done(self, report: RiskReport) -> None:
        if self.on_done:
            self.on_done(report)

    def log(self, message: str) -> None:
        if self.on_log:
            self.on_log(message)

    def phase(self, name: str, total: int) -> None:
        if self.on_phase:
            self.on_phase(name, total)


@dataclass
class Services:
    settings: Settings
    http: HttpClient
    ripe: RipeStatClient
    prefixes: PrefixResolver
    peeringdb: PeeringDbClient
    cheburcheck: CheburcheckClient
    ipapi: IpApiClient
    resolver: Resolver
    asn_names: AsnNameTable
    blocklists: BlocklistManager
    countries: CountryTable
    bundle: BlocklistBundle | None = None
    asn_resolve_cache: DiskCache = field(default_factory=lambda: DiskCache("asn-resolve"))

    @classmethod
    def build(cls, settings: Settings, http: HttpClient | None = None) -> Services:
        http = http or HttpClient(settings.network, HealthRegistry())
        ripe = RipeStatClient(settings, http)
        return cls(
            settings=settings,
            http=http,
            ripe=ripe,
            prefixes=PrefixResolver(settings, http, ripe),
            peeringdb=PeeringDbClient(settings, http),
            cheburcheck=CheburcheckClient(settings, http),
            ipapi=IpApiClient(settings, http),
            resolver=Resolver(settings, http),
            asn_names=AsnNameTable(settings, http),
            blocklists=BlocklistManager(settings, http),
            countries=load_countries(),
        )

    async def ensure_blocklists(self, force: bool = False, progress: Callable[[str], None] | None = None) -> BlocklistBundle:
        if self.bundle is None or force:
            self.bundle = await self.blocklists.load(force=force, progress=progress)
        return self.bundle

    def source_statuses(self) -> list[SourceStatus]:
        out: list[SourceStatus] = []
        for name, health in sorted(self.http.health.sources.items()):
            out.append(SourceStatus(name=name, ok=health.ok, detail=health.detail))
        if self.bundle:
            for item in self.bundle.lists:
                out.append(
                    SourceStatus(
                        name=f"list:{item.source.name}",
                        ok=item.entries > 0,
                        detail=(f"{item.entries} записей" + (", устарел" if item.stale else "")) if item.entries else item.error,
                    )
                )
        return out


def _norm_tokens(text: str) -> set[str]:
    stop = {"gmbh", "ltd", "llc", "inc", "oy", "ab", "as", "sa", "bv", "b.v.", "kft", "sro", "s.r.o.", "the", "hosting", "internet", "cloud", "online", "net", "network", "networks", "services", "solutions", "group", "limited", "co", "corp", "ag", "aps", "a/s", "oü", "uab", "sia", "srl", "spa", "zrt", "nv", "plc", "d.o.o."}
    tokens = {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3 and t not in stop}
    return tokens


def holder_matches(provider: Provider, holder: str | None) -> bool | None:
    if not holder:
        return None
    a = _norm_tokens(provider.name) | _norm_tokens(provider.asn_search or "") | _norm_tokens(provider.website_domain() or "")
    for alias in provider.aliases:
        a |= _norm_tokens(alias)
    b = _norm_tokens(holder)
    if not a or not b:
        return None
    if a & b:
        return True
    holder_joined = holder.lower().replace(" ", "")
    if any(tok in holder_joined for tok in a if len(tok) >= 4):
        return True
    # «Hostpoint AG» ↔ провайдер «hostpoint-hosting»: токен держателя целиком входит в название провайдера
    name_joined = "".join(sorted(a, key=len, reverse=True))
    return any(tok in name_joined for tok in b if len(tok) >= 4)


class AnalysisEngine:
    def __init__(self, services: Services, hooks: ProgressHooks | None = None) -> None:
        self.s = services
        self.hooks = hooks or ProgressHooks()
        self.settings = services.settings

    # ───────────────────────── ASN resolution ─────────────────────────
    async def resolve_asns(self, provider: Provider) -> tuple[list[int], str]:
        if provider.asns:
            return list(provider.asns[:MAX_ASNS_PER_PROVIDER]), "db"
        term = provider.asn_search or provider.name
        cache_key = f"{provider.id}|{term}"
        cached = self.s.asn_resolve_cache.get(cache_key, self.settings.cache.ripestat_ttl_hours * 3600)
        if cached:
            return list(cached), "cache"
        found: list[int] = []
        try:
            for sugg in await self.s.ripe.search(term):
                if sugg["category"].lower().startswith("asn") or str(sugg.get("value", "")).upper().startswith("AS"):
                    match = re.search(r"AS(\d+)", str(sugg.get("value") or sugg.get("label") or ""), re.I)
                    desc = f"{sugg.get('label') or ''} {sugg.get('desc') or ''}"
                    if match and (_norm_tokens(term) & _norm_tokens(desc) or term.lower().replace(" ", "") in desc.lower().replace(" ", "")):
                        found.append(int(match.group(1)))
        except HttpError:
            pass
        if not found:
            records = await self.s.asn_names.search(term, limit=20)
            preferred = [r for r in records if r.country == provider.hq_country]
            found = [r.asn for r in (preferred or records)]
        found = list(dict.fromkeys(found))[:MAX_ASNS_PER_PROVIDER]
        if found:
            self.s.asn_resolve_cache.set(cache_key, found)
        return found, "search"

    # ───────────────────────── per-ASN data ─────────────────────────
    async def collect_prefix_data(self, provider: Provider, asn: int, bundle: BlocklistBundle | None, prefer: str = "ripestat") -> AsnInfo:
        """Префиксы ASN и их пересечение со списками блокировок / CDN — только локальные вычисления после загрузки префиксов."""
        info = AsnInfo(asn=asn)
        prefixes, source = await self.s.prefixes.prefixes(asn, prefer=prefer)
        info.prefix_source = source
        info.prefixes_v4 = [p for p in prefixes if ":" not in p]
        info.prefixes_v6 = [p for p in prefixes if ":" in p]
        info.ipv4_count = sum(ipv4_size(p) for p in info.prefixes_v4)
        if bundle is not None and bundle.ok_lists:
            blocked_total = 0
            for prefix in info.prefixes_v4:
                blocked, size, hits = bundle.blocked_overlap(prefix)
                if blocked:
                    blocked_total += blocked
                    info.blocked_prefixes.append(prefix)
            info.blocked_ipv4_count = blocked_total
            info.blocked_share = blocked_total / info.ipv4_count if info.ipv4_count else 0.0
        if bundle is not None and bundle.cdn:
            info.cdn_prefixes = [p for p in info.prefixes_v4 if bundle.cdn_provider_for(p)]
        if provider.source == "catalog" and provider.pdb_types:
            # снимок PeeringDB из каталога — без сетевого запроса на каждый ASN
            info.peeringdb = {"info_types": list(provider.pdb_types), "info_traffic": provider.pdb_traffic, "info_scope": None}
        return info

    async def enrich_asn(self, provider: Provider, info: AsnInfo) -> AsnInfo:
        """Холдер, страна и тип сети (PeeringDB) — запросы к внешним источникам, нужны только для полной проверки."""
        if info.holder is None:
            try:
                overview = await self.s.ripe.as_overview(info.asn)
                info.holder = overview.get("holder")
            except HttpError:
                record = await self.s.asn_names.get(info.asn)
                if record:
                    info.holder = record.description or record.handle
                    info.country = record.country
        if info.country is None:
            record = await self.s.asn_names.get(info.asn) if self.s.asn_names.loaded else None
            if record:
                info.country = record.country
        info.holder_matches_provider = holder_matches(provider, info.holder)
        if info.peeringdb is None:
            try:
                info.peeringdb = await self.s.peeringdb.net_by_asn(info.asn)
            except HttpError:
                info.peeringdb = None
        return info

    async def collect_asn(self, provider: Provider, asn: int, bundle: BlocklistBundle | None) -> AsnInfo:
        info = await self.collect_prefix_data(provider, asn, bundle)
        return await self.enrich_asn(provider, info)

    # ───────────────────────── provider ─────────────────────────
    async def analyze(
        self, provider: Provider, query: SearchQuery | None = None, mode: str = "full", previous: RiskReport | None = None
    ) -> RiskReport:
        """Оценка провайдера.

        mode="quick" — только префиксы и локальные списки блокировок (быстро, без лимитов внешних API);
        mode="full" — плюс cheburcheck, ip-api, PeeringDB, живые пробы. previous — результат быстрой проверки:
        его префиксы переиспользуются, а не запрашиваются заново.
        """
        quick = mode == "quick"
        query = query or SearchQuery()
        started = time.monotonic()
        report = RiskReport(provider=provider, depth="quick" if quick else "full")
        report.matched_locations = provider.locations_in(query.countries) if query.countries else list(provider.locations)
        bundle = self.s.bundle
        lists_ok = bool(bundle and bundle.ok_lists)
        weights = self.settings.scoring.weights
        cfg_cc = self.settings.sources.cheburcheck

        self.hooks.stage(provider, "asn", "определение ASN")
        asns, how = await self.resolve_asns(provider)
        if not asns:
            report.warnings.append("Не удалось определить ASN провайдера — сетевые сигналы недоступны")
        elif how == "search":
            report.warnings.append("ASN найден поиском по названию — проверьте holder в отчёте")

        self.hooks.stage(provider, "prefixes", f"префиксы и списки блокировок ({len(asns)} ASN)")
        known = {a.asn: a for a in previous.asns} if previous is not None else {}
        for asn in asns:
            try:
                info = known.get(asn) or await self.collect_prefix_data(provider, asn, bundle, prefer="ipverse" if quick else "ripestat")
                report.asns.append(info if quick else await self.enrich_asn(provider, info))
            except Exception as exc:  # noqa: BLE001
                report.warnings.append(f"AS{asn}: ошибка сбора данных ({exc})")
        for a in report.asns:
            if a.holder_matches_provider is False:
                report.warnings.append(f"AS{a.asn}: holder «{a.holder}» не похож на название провайдера — проверьте ASN")

        # cheburcheck
        cc_asn_results: list[dict[str, Any]] = []
        cc_site: dict[str, Any] | None = None
        cc_error: str | None = None
        domain = provider.website_domain()
        if cfg_cc.enabled and not quick:
            self.hooks.stage(provider, "cheburcheck", "запросы к cheburcheck.ru")
            if cfg_cc.check_asn:
                for a in report.asns[:MAX_CHEBURCHECK_ASNS]:
                    try:
                        res = await self.s.cheburcheck.check(f"AS{a.asn}")
                        if res:
                            cc_asn_results.append(res)
                    except HttpError as exc:
                        cc_error = str(exc)
                        break
            if cfg_cc.check_website and domain and cc_error is None:
                try:
                    cc_site = await self.s.cheburcheck.check(domain)
                except HttpError as exc:
                    cc_error = str(exc)

        # ip-api sampling
        ipapi_data: dict[str, dict[str, Any]] = {}
        sample: list[str] = []
        if self.settings.sources.ipapi.enabled and report.asns and not quick:
            self.hooks.stage(provider, "ipapi", "классификация IP-пула")
            sample = self._sample_from_asns(report.asns, self.settings.sources.ipapi.samples_per_asn)
            if sample:
                try:
                    ipapi_data = await self.s.ipapi.lookup_many(sample)
                except HttpError:
                    ipapi_data = {}

        # live probe
        probe_outcomes: list[dict[str, Any]] | None = None
        control_ok: bool | None = None
        website_ips: list[str] = []
        live_enabled = (query.live_probe or self.settings.live_probe.enabled) and not quick
        if live_enabled:
            self.hooks.stage(provider, "probe", "живые TCP-пробы")
            control_ok = await control_reachable(self.settings.live_probe)
            if control_ok:
                targets = self._sample_from_asns(report.asns, self.settings.live_probe.samples_per_asn)
                if domain:
                    website_ips = [ip for ip in await self.s.resolver.resolve(domain)][:2]
                    targets = website_ips + [t for t in targets if t not in website_ips]
                if targets:
                    outcomes = await probe_many(targets, self.settings.live_probe)
                    probe_outcomes = [{"ip": o.ip, "port": o.port, "result": o.result, "latency_ms": o.latency_ms} for o in outcomes]

        self.hooks.stage(provider, "score", "расчёт оценки")
        matched_cc = [loc.country for loc in report.matched_locations]
        report.signals = [
            sig.blocklist_overlap(report.asns, weights, lists_ok),
            sig.cheburcheck_asn(cc_asn_results, weights, cfg_cc.enabled and cfg_cc.check_asn, cc_error, quick),
            sig.cheburcheck_site(cc_site, domain, weights, cfg_cc.enabled and cfg_cc.check_website, cc_error, quick),
            sig.asn_size(report.asns, weights, self.settings.scoring.thresholds.small_asn_ipv4),
            sig.network_type(provider, report.asns, ipapi_data, weights),
            sig.popularity(provider, weights),
            sig.jurisdiction(provider, matched_cc, self.s.countries, weights),
            sig.cdn_membership(report.asns, weights, bool(bundle and bundle.cdn)),
            sig.ru_ties(provider, weights),
            sig.complaints(cc_asn_results + ([cc_site] if cc_site else []), weights, cfg_cc.enabled, quick),
            sig.live_probe(probe_outcomes, control_ok, website_ips, weights, live_enabled),
            sig.asn_fragmentation(report.asns, weights),
        ]
        score_report(report, self.settings.scoring, self.s.countries)
        report.duration_seconds = round(time.monotonic() - started, 2)
        self.hooks.done(report)
        return report

    @staticmethod
    def _sample_from_asns(asns: list[AsnInfo], per_asn: int) -> list[str]:
        out: list[str] = []
        for a in asns:
            prefixes = sorted(a.prefixes_v4, key=ipv4_size, reverse=True)
            if not prefixes:
                continue
            chosen = prefixes[: max(1, per_asn // 2)]
            if len(prefixes) > len(chosen):
                chosen += prefixes[len(prefixes) // 2 : len(prefixes) // 2 + 1]
            per_prefix = max(1, per_asn // max(1, len(chosen)))
            for prefix in chosen:
                out.extend(sample_ips(prefix, per_prefix))
        return list(dict.fromkeys(out))[: per_asn * max(1, len(asns))]

    # ───────────────────────── batch ─────────────────────────
    async def _run_batch(
        self, providers: list[Provider], query: SearchQuery, mode: str, previous: dict[str, RiskReport] | None = None
    ) -> list[RiskReport]:
        semaphore = asyncio.Semaphore(max(1, self.settings.network.concurrency))
        reports: list[RiskReport] = []

        async def worker(provider: Provider) -> None:
            async with semaphore:
                try:
                    reports.append(await self.analyze(provider, query, mode, (previous or {}).get(provider.id)))
                except Exception as exc:  # noqa: BLE001
                    report = RiskReport(provider=provider, warnings=[f"Анализ прерван ошибкой: {exc}"])
                    score_report(report, self.settings.scoring, self.s.countries)
                    reports.append(report)
                    self.hooks.done(report)

        await asyncio.gather(*(worker(p) for p in providers))
        return reports

    async def run_search(
        self, providers: list[Provider], query: SearchQuery, title: str | None = None, plan: selection.Plan | None = None
    ) -> SearchResult:
        """Анализ списка провайдеров.

        Малые списки проверяются полностью. Большие — в две фазы: быстрая проверка всех по локальным данным, затем
        полная (cheburcheck и др.) только для лучших на каждую локацию. Если после полной проверки лучшие «просели»,
        в топ поднимаются следующие, и их тоже проверяют (до MAX_DEEP_ROUNDS раундов).
        """
        started = time.monotonic()
        by_id = {p.id: p for p in providers}
        reports: dict[str, RiskReport] = {}
        if query.deep_per_location <= 0:
            self.hooks.phase("quick", len(providers))
            reports = {r.provider.id: r for r in await self._run_batch(providers, query, "quick")}
        elif len(providers) <= FULL_ANALYSIS_MAX:
            self.hooks.phase("full", len(providers))
            reports = {r.provider.id: r for r in await self._run_batch(providers, query, "full")}
        else:
            self.hooks.phase("quick", len(providers))
            reports = {r.provider.id: r for r in await self._run_batch(providers, query, "quick")}
            for _ in range(MAX_DEEP_ROUNDS):
                need = selection.deep_targets(selection.filter_reports(list(reports.values()), query), query)
                if not need:
                    break
                self.hooks.phase("deep", len(need))
                deep = await self._run_batch([by_id[pid] for pid in need], query, "full", previous=reports)
                reports.update({r.provider.id: r for r in deep})
        final = selection.filter_reports(list(reports.values()), query)
        result = SearchResult(
            query=query,
            reports=final,
            sources=self.s.source_statuses(),
            picks=selection.build_picks(final, query, group_counts=plan.groups if plan else None),
            candidates_total=plan.matched if plan else len(providers),
            candidates_analyzed=len(providers),
        )
        result.duration_seconds = round(time.monotonic() - started, 1)
        if title:
            result.title = title
        return result

    async def analyze_target(self, target: str) -> RiskReport:
        """Произвольная цель: ASN, IP или домен → временный провайдер."""
        target = target.strip()
        provider = await self.provider_from_target(target)
        return await self.analyze(provider)

    async def provider_from_target(self, target: str) -> Provider:
        target = target.strip()
        m = re.fullmatch(r"(?i)as?(\d+)", target)
        if m:
            asn = int(m.group(1))
            holder = None
            country = "ZZ"
            try:
                overview = await self.s.ripe.as_overview(asn)
                holder = overview.get("holder")
            except HttpError:
                pass
            record = await self.s.asn_names.get(asn)
            if record:
                holder = holder or record.description
                country = record.country or country
            name = holder or f"AS{asn}"
            return Provider(id=f"as{asn}", name=name, asns=[asn], hq_country=country, locations=[Location(country=country)] if country != "ZZ" else [], source="adhoc", popularity_ru=2, ip_type="unknown")
        ip_match = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", target) or (":" in target and re.fullmatch(r"[0-9a-fA-F:]+", target))
        if ip_match:
            try:
                net = await self.s.ripe.network_info(target)
                asns = net.get("asns") or []
            except HttpError:
                asns = []
            geo = await self.s.ripe.geo_for_ip(target)
            country = (geo.get("country") or "ZZ").upper()
            return Provider(id=f"ip-{target}", name=f"IP {target}", asns=asns[:MAX_ASNS_PER_PROVIDER], hq_country=country, locations=[Location(country=country, city=geo.get("city"))] if country != "ZZ" else [], source="adhoc", popularity_ru=2, ip_type="unknown")
        domain = target.lower().removeprefix("https://").removeprefix("http://").split("/")[0].removeprefix("www.")
        ips = await self.s.resolver.resolve(domain)
        asns: list[int] = []
        country = "ZZ"
        city = None
        if ips:
            try:
                net = await self.s.ripe.network_info(ips[0])
                asns = net.get("asns") or []
            except HttpError:
                pass
            geo = await self.s.ripe.geo_for_ip(ips[0])
            country = (geo.get("country") or "ZZ").upper()
            city = geo.get("city")
        return Provider(id=f"domain-{domain}", name=domain, website=f"https://{domain}", asns=asns[:MAX_ASNS_PER_PROVIDER], hq_country=country, locations=[Location(country=country, city=city)] if country != "ZZ" else [], source="adhoc", popularity_ru=2, ip_type="unknown")
