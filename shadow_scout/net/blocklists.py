"""Загрузка, кеширование и индексирование списков блокировок (antifilter, Re:filter, CDN)."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

from shadow_scout.cache import FileCache
from shadow_scout.config import BlocklistSource, Settings
from shadow_scout.net.http import HttpClient, HttpError
from shadow_scout.net.ipindex import NetworkSet


@dataclass
class LoadedList:
    source: BlocklistSource
    networks: NetworkSet
    entries: int
    age_hours: float | None
    stale: bool
    error: str = ""


@dataclass
class CdnRecord:
    provider: str
    cidr: str
    region: str | None


@dataclass
class BlocklistBundle:
    lists: list[LoadedList] = field(default_factory=list)
    cdn: dict[str, NetworkSet] = field(default_factory=dict)  # provider -> сеть
    cdn_entries: int = 0

    @property
    def ok_lists(self) -> list[LoadedList]:
        return [item for item in self.lists if item.entries > 0]

    def blocked_overlap(self, cidr: str) -> tuple[int, int, list[str]]:
        """Максимальная по спискам доля заблокированных адресов и имена сработавших списков."""
        best = 0
        total = 0
        hits: list[str] = []
        for item in self.ok_lists:
            blocked, size = item.networks.overlap_cidr(cidr)
            total = size
            if blocked:
                hits.append(item.source.name)
                if blocked > best:
                    best = blocked
        return best, total, hits

    def is_blocked_ip(self, ip: str) -> list[str]:
        return [item.source.name for item in self.ok_lists if item.networks.contains_ip(ip)]

    def cdn_provider_for(self, cidr: str) -> str | None:
        for provider, nets in self.cdn.items():
            blocked, size = nets.overlap_cidr(cidr)
            if size and blocked * 2 >= size:
                return provider
        return None

    def summary(self) -> str:
        parts = []
        for item in self.lists:
            if item.entries:
                age = f"{item.age_hours:.0f}ч" if item.age_hours is not None else "?"
                flag = " (устар.)" if item.stale else ""
                parts.append(f"{item.source.name}: {item.entries:,} записей, {age}{flag}".replace(",", " "))
            else:
                parts.append(f"{item.source.name}: нет данных ({item.error})")
        if self.cdn_entries:
            parts.append(f"CDN: {self.cdn_entries:,} префиксов".replace(",", " "))
        return "\n".join(parts)


class BlocklistManager:
    def __init__(self, settings: Settings, http: HttpClient, cache: FileCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or FileCache("blocklists")

    def ttl_seconds(self) -> float:
        return self.settings.cache.blocklists_ttl_hours * 3600

    async def fetch_source(self, source: BlocklistSource, force: bool = False) -> tuple[str | None, bool, str]:
        """Возвращает (текст, устарел ли, ошибка)."""
        key = source.url
        text = None if force else self.cache.get(key, self.ttl_seconds())
        if text is not None:
            return text, False, ""
        try:
            fresh = await self.http.get_text(source.url, source=f"blocklist:{source.name}", timeout=90)
            if fresh.strip():
                self.cache.set(key, fresh)
                return fresh, False, ""
            error = "пустой ответ"
        except HttpError as exc:
            error = str(exc)
        stale = self.cache.get_stale(key)
        if stale is not None:
            return stale, True, error
        return None, False, error

    async def load(self, force: bool = False, progress=None) -> BlocklistBundle:
        bundle = BlocklistBundle()
        for source in self.settings.sources.blocklists:
            if not source.enabled:
                continue
            if progress:
                progress(f"Список: {source.name}")
            text, stale, error = await self.fetch_source(source, force=force)
            age = self.cache.age_seconds(source.url)
            age_hours = age / 3600 if age is not None else None
            if text is None:
                bundle.lists.append(LoadedList(source, NetworkSet(), 0, age_hours, False, error or "нет данных"))
                continue
            if source.kind == "cdn_csv":
                self._load_cdn(bundle, text)
                continue
            nets = NetworkSet()
            entries = nets.add_many(text.splitlines())
            bundle.lists.append(LoadedList(source, nets, entries, age_hours, stale, error))
        return bundle

    def _load_cdn(self, bundle: BlocklistBundle, text: str) -> None:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            provider = (row.get("provider") or "").strip().lower()
            cidr = (row.get("cidr") or "").strip()
            if not provider or not cidr:
                continue
            nets = bundle.cdn.setdefault(provider, NetworkSet())
            if nets.add_cidr(cidr):
                bundle.cdn_entries += 1

    def status_lines(self) -> list[str]:
        lines = []
        for source in self.settings.sources.blocklists:
            age = self.cache.age_seconds(source.url)
            if not source.enabled:
                lines.append(f"[dim]⏸ {source.name} — отключён[/dim]")
            elif age is None:
                lines.append(f"[yellow]○ {source.name} — не загружен[/yellow]")
            else:
                hours = age / 3600
                color = "green" if hours <= self.settings.cache.blocklists_ttl_hours else "yellow"
                lines.append(f"[{color}]● {source.name} — обновлён {hours:.1f} ч назад[/{color}]")
        return lines
