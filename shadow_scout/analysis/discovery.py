"""Discovery: поиск небольших локальных ASN в выбранной стране (RIPEstat country-asns + таблица имён ASN)."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from shadow_scout.analysis.engine import Services
from shadow_scout.models import Location, Provider
from shadow_scout.net.http import HttpError
from shadow_scout.net.ipindex import ipv4_size
from shadow_scout.net.peeringdb import PeeringDbClient

DEFAULT_INCLUDE = [
    "host", "cloud", "vps", "server", "data", "dc", "colo", "web", "net", "telecom", "isp", "broadband",
    "internet", "online", "it ", "systems", "solutions", "digital", "tele", "com", "media", "fiber", "link",
]
DEFAULT_EXCLUDE = [
    "university", "universit", "school", "college", "bank", "government", "ministry", "hospital", "police",
    "municipal", "county", "city of", "research", "institute", "akadem", "academy", "insurance", "airport", "railway",
]


@dataclass
class Candidate:
    asn: int
    name: str
    country: str
    ipv4_count: int = 0
    prefixes: int = 0
    blocked_share: float = 0.0
    blocked_prefixes: int = 0
    pdb_type: str = "unknown"
    pdb_traffic: str | None = None
    pdb_scope: str | None = None
    website: str | None = None
    error: str = ""

    @property
    def score(self) -> float:
        """Чем меньше — тем лучше: сначала чистые, потом маленькие, ISP-подобные."""
        size_pen = 0.0 if self.ipv4_count <= 4096 else (0.2 if self.ipv4_count <= 16384 else (0.5 if self.ipv4_count <= 65536 else 1.0))
        type_pen = {"isp": 0.0, "enterprise": 0.1, "unknown": 0.3, "other": 0.3, "content": 0.5}.get(self.pdb_type, 0.3)
        return self.blocked_share * 10 + size_pen + type_pen

    def to_provider(self) -> Provider:
        return Provider(
            id=f"as{self.asn}",
            name=self.name or f"AS{self.asn}",
            website=self.website,
            asns=[self.asn],
            hq_country=self.country,
            locations=[Location(country=self.country)],
            size="micro" if self.ipv4_count <= 4096 else ("small" if self.ipv4_count <= 32768 else "medium"),
            popularity_ru=1,
            ip_type="isp" if self.pdb_type == "isp" else ("mixed" if self.pdb_type == "enterprise" else "unknown"),
            source="discovered",
            notes=f"Найден через discovery ({self.country}); PeeringDB: {self.pdb_type}",
            tags=["discovered", "local"],
        )


@dataclass
class DiscoveryOptions:
    country: str
    include_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE))
    exclude_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    max_candidates: int = 60
    max_ipv4: int = 262144
    min_ipv4: int = 256
    keyword_filter: bool = True


class DiscoveryEngine:
    def __init__(self, services: Services) -> None:
        self.s = services

    async def list_country_asns(self, country: str, log: Callable[[str], None] | None = None) -> list[tuple[int, str]]:
        """Список (asn, name) для страны: RIPEstat routed + имена из таблицы ipverse (или только таблица)."""
        names = await self.s.asn_names.load()
        routed: list[int] = []
        try:
            routed, _ = await self.s.ripe.country_asns(country)
            if log:
                log(f"RIPEstat: {len(routed)} маршрутизируемых ASN в {country.upper()}")
        except HttpError as exc:
            if log:
                log(f"RIPEstat недоступен ({exc}), используем таблицу ASN по стране")
        if routed:
            return [(asn, (names[asn].description if asn in names else "") or (names[asn].handle if asn in names else "")) for asn in routed]
        return [(r.asn, r.description or r.handle) for r in names.values() if r.country == country.upper()]

    @staticmethod
    def keyword_pass(name: str, include: list[str], exclude: list[str]) -> bool:
        low = f" {name.lower()} "
        if any(ex in low for ex in exclude):
            return False
        return any(inc in low for inc in include)

    async def discover(
        self,
        options: DiscoveryOptions,
        on_candidate: Callable[[Candidate], None] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> list[Candidate]:
        pairs = await self.list_country_asns(options.country, log)
        if options.keyword_filter:
            filtered = [(asn, name) for asn, name in pairs if self.keyword_pass(name, options.include_keywords, options.exclude_keywords)]
        else:
            filtered = pairs
        if log:
            log(f"После фильтра по ключевым словам: {len(filtered)} ASN (анализируем до {options.max_candidates})")
        filtered = filtered[: options.max_candidates]
        bundle = await self.s.ensure_blocklists()
        semaphore = asyncio.Semaphore(max(1, self.s.settings.network.concurrency))
        results: list[Candidate] = []

        async def worker(asn: int, name: str) -> None:
            async with semaphore:
                cand = Candidate(asn=asn, name=name, country=options.country.upper())
                try:
                    prefixes, _ = await self.s.prefixes.prefixes(asn)
                    v4 = [p for p in prefixes if ":" not in p]
                    cand.prefixes = len(v4)
                    cand.ipv4_count = sum(ipv4_size(p) for p in v4)
                    if bundle.ok_lists:
                        blocked = 0
                        for p in v4:
                            b, _size, _hits = bundle.blocked_overlap(p)
                            if b:
                                blocked += b
                                cand.blocked_prefixes += 1
                        cand.blocked_share = blocked / cand.ipv4_count if cand.ipv4_count else 0.0
                    try:
                        pdb = await self.s.peeringdb.net_by_asn(asn)
                    except HttpError:
                        pdb = None
                    if pdb:
                        cand.pdb_type = PeeringDbClient.classify(pdb)
                        cand.pdb_traffic = pdb.get("info_traffic")
                        cand.pdb_scope = pdb.get("info_scope")
                        cand.website = pdb.get("website")
                        if not cand.name and pdb.get("name"):
                            cand.name = pdb["name"]
                except Exception as exc:  # noqa: BLE001
                    cand.error = str(exc)
                if options.min_ipv4 <= cand.ipv4_count <= options.max_ipv4 or cand.error:
                    results.append(cand)
                    if on_candidate:
                        on_candidate(cand)

        await asyncio.gather(*(worker(asn, name) for asn, name in filtered))
        results.sort(key=lambda c: (c.score, c.ipv4_count))
        return results


def parse_keywords(text: str) -> list[str]:
    return [k.strip().lower() for k in re.split(r"[,;\n]", text) if k.strip()]
