"""Клиент cheburcheck.ru (/api/v1/check, /api/v1/status). Совместим с self-hosted инстансами."""

from __future__ import annotations

from typing import Any

from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError


class CheburcheckClient:
    def __init__(self, settings: Settings, http: HttpClient, cache: DiskCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or DiskCache("cheburcheck")
        self.cfg = settings.sources.cheburcheck
        self.name = "cheburcheck"

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    async def status(self) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            self.http.health.mark_disabled(self.name)
            return None
        try:
            data = await self.http.get_json(
                f"{self.cfg.base_url.rstrip('/')}/api/v1/status",
                source=self.name,
                per_minute=self.cfg.requests_per_minute,
                timeout=15,
            )
        except HttpError:
            return None
        return data if isinstance(data, dict) else None

    async def check(self, target: str) -> dict[str, Any] | None:
        """Возвращает нормализованный ответ /api/v1/check или None (404 — цель не найдена)."""
        if not self.cfg.enabled:
            self.http.health.mark_disabled(self.name)
            raise HttpError("cheburcheck отключён в настройках")
        target = target.strip()
        try:
            data = await self.http.get_json(
                f"{self.cfg.base_url.rstrip('/')}/api/v1/check",
                source=self.name,
                per_minute=self.cfg.requests_per_minute,
                params={"target": target},
                headers={"Accept": "application/json"},
                cache=self.cache,
                ttl_seconds=self.settings.cache.cheburcheck_ttl_hours * 3600,
                timeout=45,
            )
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise
        if not isinstance(data, dict):
            return None
        return normalize_check(data)


def normalize_check(data: dict[str, Any]) -> dict[str, Any]:
    asn_info = data.get("asn_info") or None
    complaints = data.get("complaints") or []
    complaints_total = 0
    for day in complaints:
        try:
            complaints_total += int(day.get("count", 0))
        except (TypeError, ValueError, AttributeError):
            pass
    cdn = data.get("cdn_providers") or {}
    geo = data.get("geo") or {}
    return {
        "id": data.get("id"),
        "target": data.get("target"),
        "target_type": data.get("target_type"),
        "blocked": bool(data.get("blocked")),
        "rkn_domain": data.get("rkn_domain"),
        "ips": data.get("ips") or [],
        "blocked_subnets": data.get("blocked_subnets") or [],
        "cdn_providers": sorted(cdn.keys()),
        "geo": {
            "asn": geo.get("asn"),
            "country_code": geo.get("country_code"),
            "organisation": geo.get("organisation"),
            "location": geo.get("location"),
        },
        "asn_info": {
            "asn": asn_info.get("asn"),
            "prefixes": asn_info.get("prefixes") or [],
            "blocked_prefixes": asn_info.get("blocked_prefixes") or [],
        }
        if asn_info
        else None,
        "complaints": complaints,
        "complaints_total": complaints_total,
        "subnet_size": data.get("subnet_size"),
        "reverse_lookup": data.get("reverse_lookup") or [],
    }
