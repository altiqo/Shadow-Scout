"""Получение префиксов ASN: RIPEstat (живые данные BGP) и ipverse/asn-ip на GitHub (быстро, без лимитов)."""

from __future__ import annotations

from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError
from shadow_scout.net.ripestat import RipeStatClient


class PrefixResolver:
    def __init__(self, settings: Settings, http: HttpClient, ripe: RipeStatClient, cache: DiskCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.ripe = ripe
        self.cache = cache or DiskCache("prefixes")
        self.name = "ipverse"

    async def _from_ripestat(self, asn: int) -> list[str]:
        try:
            return await self.ripe.announced_prefixes(asn)
        except HttpError:
            return []

    async def _from_ipverse(self, asn: int) -> list[str] | None:
        url = self.settings.sources.fallback.asn_prefixes_template.format(asn=asn)
        ttl = self.settings.cache.ripestat_ttl_hours * 3600
        cached = self.cache.get(url, ttl)
        if cached is not None:
            return list(cached)
        try:
            text = await self.http.get_text(url, source=self.name, timeout=30)
        except HttpError:
            return None
        prefixes = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        self.cache.set(url, prefixes)
        return prefixes

    async def prefixes(self, asn: int, prefer: str = "ripestat") -> tuple[list[str], str]:
        """Возвращает (список префиксов, имя источника).

        prefer="ripestat" — сначала RIPEstat (точнее, но лимит запросов), запасной ipverse;
        prefer="ipverse" — наоборот: быстрая массовая выборка, RIPEstat только если ipverse не знает ASN.
        """
        if prefer == "ipverse":
            fast = await self._from_ipverse(asn)
            if fast:
                return fast, "ipverse"
            prefixes = await self._from_ripestat(asn)
            return (prefixes, "ripestat") if prefixes else ([], "none")
        prefixes = await self._from_ripestat(asn)
        if prefixes:
            return prefixes, "ripestat"
        fallback = await self._from_ipverse(asn)
        return (fallback, "ipverse") if fallback is not None else ([], "none")
