"""Получение префиксов ASN: RIPEstat (основной) с запасным источником ipverse/asn-ip на GitHub."""

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

    async def prefixes(self, asn: int) -> tuple[list[str], str]:
        """Возвращает (список префиксов, имя источника)."""
        try:
            prefixes = await self.ripe.announced_prefixes(asn)
            if prefixes:
                return prefixes, "ripestat"
        except HttpError:
            pass
        url = self.settings.sources.fallback.asn_prefixes_template.format(asn=asn)
        ttl = self.settings.cache.ripestat_ttl_hours * 3600
        cached = self.cache.get(url, ttl)
        if cached is not None:
            return list(cached), "ipverse"
        try:
            text = await self.http.get_text(url, source=self.name, timeout=30)
        except HttpError:
            return [], "none"
        prefixes = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        self.cache.set(url, prefixes)
        return prefixes, "ipverse"
