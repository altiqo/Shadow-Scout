"""Таблица ASN → (название, страна) из ipverse/asn-info (GitHub) — запасной источник и база для discovery."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

from shadow_scout.cache import FileCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError


@dataclass(frozen=True)
class AsnRecord:
    asn: int
    handle: str
    description: str
    country: str


class AsnNameTable:
    def __init__(self, settings: Settings, http: HttpClient, cache: FileCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or FileCache("asn-names")
        self._records: dict[int, AsnRecord] | None = None
        self.name = "asn-names"

    async def load(self, force: bool = False) -> dict[int, AsnRecord]:
        if self._records is not None and not force:
            return self._records
        url = self.settings.sources.fallback.asn_names_csv
        ttl = self.settings.cache.asn_names_ttl_hours * 3600
        text = None if force else self.cache.get(url, ttl)
        if text is None:
            try:
                text = await self.http.get_text(url, source=self.name, timeout=120)
                self.cache.set(url, text)
            except HttpError:
                text = self.cache.get_stale(url)
        records: dict[int, AsnRecord] = {}
        if text:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                try:
                    asn = int(row.get("asn") or "")
                except ValueError:
                    continue
                records[asn] = AsnRecord(
                    asn=asn,
                    handle=(row.get("handle") or "").strip(),
                    description=(row.get("description") or "").strip(),
                    country=(row.get("country-code") or "").strip().upper(),
                )
        self._records = records
        return records

    async def get(self, asn: int) -> AsnRecord | None:
        records = await self.load()
        return records.get(asn)

    async def by_country(self, country: str) -> list[AsnRecord]:
        records = await self.load()
        cc = country.upper()
        return [r for r in records.values() if r.country == cc]

    async def search(self, term: str, limit: int = 30) -> list[AsnRecord]:
        records = await self.load()
        needle = term.lower()
        out = [r for r in records.values() if needle in r.description.lower() or needle in r.handle.lower()]
        out.sort(key=lambda r: (len(r.description), r.asn))
        return out[:limit]

    @property
    def loaded(self) -> bool:
        return bool(self._records)
