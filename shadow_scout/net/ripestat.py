"""Клиент RIPEstat Data API (без ключа): префиксы ASN, холдер, поиск, ASN по стране, сеть по IP."""

from __future__ import annotations

import re
from typing import Any

from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError

SOURCEAPP = "shadow-scout"


class RipeStatClient:
    def __init__(self, settings: Settings, http: HttpClient, cache: DiskCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or DiskCache("ripestat")
        self.cfg = settings.sources.ripestat
        self.name = "ripestat"

    @property
    def ttl(self) -> float:
        return self.settings.cache.ripestat_ttl_hours * 3600

    async def _call(self, endpoint: str, resource: str, ttl: float | None = None, **extra: Any) -> dict[str, Any]:
        if not self.cfg.enabled:
            self.http.health.mark_disabled(self.name)
            raise HttpError("RIPEstat отключён в настройках")
        params = {"resource": resource, "sourceapp": SOURCEAPP, **extra}
        url = f"{self.cfg.base_url.rstrip('/')}/{endpoint}/data.json"
        data = await self.http.get_json(
            url,
            source=self.name,
            per_minute=self.cfg.requests_per_minute,
            params=params,
            cache=self.cache,
            ttl_seconds=self.ttl if ttl is None else ttl,
        )
        if not isinstance(data, dict) or data.get("status") not in (None, "ok"):
            raise HttpError(f"RIPEstat {endpoint}: {data.get('status') if isinstance(data, dict) else 'bad'}")
        return data.get("data", {}) or {}

    async def announced_prefixes(self, asn: int) -> list[str]:
        data = await self._call("announced-prefixes", f"AS{asn}")
        prefixes = [p.get("prefix") for p in data.get("prefixes", []) if p.get("prefix")]
        return sorted(set(prefixes))

    async def as_overview(self, asn: int) -> dict[str, Any]:
        data = await self._call("as-overview", f"AS{asn}")
        return {
            "asn": asn,
            "holder": data.get("holder"),
            "announced": data.get("announced"),
            "block": data.get("block") or {},
        }

    async def abuse_contacts(self, asn: int) -> list[str]:
        """Почтовые адреса abuse-контактов ASN (по домену можно угадать сайт оператора)."""
        data = await self._call("abuse-contact-finder", f"AS{asn}")
        return [c for c in data.get("abuse_contacts", []) if isinstance(c, str) and "@" in c]

    async def network_info(self, ip: str) -> dict[str, Any]:
        data = await self._call("network-info", ip)
        asns = [int(a) for a in data.get("asns", []) if str(a).isdigit()]
        return {"asns": asns, "prefix": data.get("prefix")}

    async def search(self, term: str) -> list[dict[str, Any]]:
        """searchcomplete: подсказки по имени организации/ASN."""
        data = await self._call("searchcomplete", term, ttl=self.ttl)
        out: list[dict[str, Any]] = []
        for category in data.get("categories", []):
            cat = category.get("category", "")
            for sugg in category.get("suggestions", []):
                out.append({"category": cat, "label": sugg.get("label"), "value": sugg.get("value"), "desc": sugg.get("description")})
        return out

    async def country_asns(self, country: str) -> tuple[list[int], list[int]]:
        """ASN, зарегистрированные в стране: (маршрутизируемые, немаршрутизируемые)."""
        data = await self._call("country-asns", country.lower(), lod=1, ttl=self.ttl)
        routed: list[int] = []
        non_routed: list[int] = []
        for entry in data.get("countries", []):
            routed.extend(_parse_asn_list(entry.get("routed", [])))
            non_routed.extend(_parse_asn_list(entry.get("non_routed", [])))
        return sorted(set(routed)), sorted(set(non_routed))

    async def geo_for_ip(self, ip: str) -> dict[str, Any]:
        try:
            data = await self._call("maxmind-geo-lite", ip)
        except HttpError:
            return {}
        located = data.get("located_resources", [])
        if located and located[0].get("locations"):
            loc = located[0]["locations"][0]
            return {"country": loc.get("country"), "city": loc.get("city")}
        return {}


_ASN_RE = re.compile(r"AS?(\d+)", re.IGNORECASE)


def _parse_asn_list(values: list[Any]) -> list[int]:
    out: list[int] = []
    for value in values:
        if isinstance(value, int):
            out.append(value)
            continue
        match = _ASN_RE.search(str(value))
        if match:
            out.append(int(match.group(1)))
    return out
