"""Клиент ip-api.com (batch): признак hosting/proxy/mobile и организация для выборки адресов."""

from __future__ import annotations

from typing import Any

from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError

FIELDS = "status,message,query,countryCode,isp,org,as,asname,hosting,proxy,mobile"


class IpApiClient:
    def __init__(self, settings: Settings, http: HttpClient, cache: DiskCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or DiskCache("ipapi")
        self.cfg = settings.sources.ipapi
        self.name = "ip-api"

    async def lookup_many(self, ips: list[str]) -> dict[str, dict[str, Any]]:
        if not self.cfg.enabled:
            self.http.health.mark_disabled(self.name)
            return {}
        ttl = self.settings.cache.ipapi_ttl_hours * 3600
        result: dict[str, dict[str, Any]] = {}
        pending: list[str] = []
        for ip in ips:
            cached = self.cache.get(f"ipapi:{ip}", ttl)
            if cached is not None:
                result[ip] = cached
            else:
                pending.append(ip)
        for i in range(0, len(pending), 100):
            chunk = pending[i : i + 100]
            try:
                data = await self.http.post_json(
                    f"{self.cfg.base_url.rstrip('/')}/batch",
                    [{"query": ip, "fields": FIELDS} for ip in chunk],
                    source=self.name,
                    per_minute=self.cfg.requests_per_minute,
                    timeout=30,
                )
            except HttpError:
                break
            if not isinstance(data, list):
                break
            for item in data:
                if not isinstance(item, dict):
                    continue
                ip = item.get("query")
                if not ip:
                    continue
                entry = {
                    "ok": item.get("status") == "success",
                    "country": item.get("countryCode"),
                    "isp": item.get("isp"),
                    "org": item.get("org"),
                    "as": item.get("as"),
                    "asname": item.get("asname"),
                    "hosting": bool(item.get("hosting")),
                    "proxy": bool(item.get("proxy")),
                    "mobile": bool(item.get("mobile")),
                }
                self.cache.set(f"ipapi:{ip}", entry)
                result[ip] = entry
        return result
