"""Клиент PeeringDB: тип сети, масштаб трафика, охват, сайт."""

from __future__ import annotations

from typing import Any

from shadow_scout.cache import DiskCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError

ISP_TYPES = {"Cable/DSL/ISP", "NSP", "Network Services"}
CONTENT_TYPES = {"Content"}
TRAFFIC_ORDER = [
    "0-20Mbps", "20-100Mbps", "100-1000Mbps", "1-5Gbps", "5-10Gbps", "10-20Gbps", "20-50Gbps",
    "50-100Gbps", "100-200Gbps", "200-300Gbps", "300-500Gbps", "500-1000Gbps", "1-5Tbps", "5-10Tbps",
    "10-20Tbps", "20-50Tbps", "50-100Tbps", "100+Tbps",
]


class PeeringDbClient:
    def __init__(self, settings: Settings, http: HttpClient, cache: DiskCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or DiskCache("peeringdb")
        self.cfg = settings.sources.peeringdb
        self.name = "peeringdb"

    async def net_by_asn(self, asn: int) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            self.http.health.mark_disabled(self.name)
            return None
        headers = {}
        if self.cfg.api_key:
            headers["Authorization"] = f"Api-Key {self.cfg.api_key}"
        url = f"{self.cfg.base_url.rstrip('/')}/net"
        data = await self.http.get_json(
            url,
            source=self.name,
            per_minute=self.cfg.requests_per_minute,
            params={"asn": asn},
            headers=headers or None,
            cache=self.cache,
            ttl_seconds=self.settings.cache.peeringdb_ttl_hours * 3600,
        )
        items = data.get("data") if isinstance(data, dict) else None
        if not items:
            return None
        net = items[0]
        info_types = [t for t in (net.get("info_types") or []) if t]
        if not info_types and net.get("info_type"):
            info_types = [net["info_type"]]
        return {
            "name": net.get("name"),
            "aka": net.get("aka"),
            "website": net.get("website"),
            "info_type": info_types[0] if info_types else None,
            "info_types": info_types,
            "info_traffic": net.get("info_traffic"),
            "info_scope": net.get("info_scope"),
            "info_prefixes4": net.get("info_prefixes4"),
            "info_prefixes6": net.get("info_prefixes6"),
            "policy_general": net.get("policy_general"),
            "ix_count": net.get("ix_count"),
            "fac_count": net.get("fac_count"),
        }

    @staticmethod
    def traffic_rank(label: str | None) -> int | None:
        if not label:
            return None
        try:
            return TRAFFIC_ORDER.index(label)
        except ValueError:
            return None

    @staticmethod
    def classify(net: dict[str, Any] | None) -> str:
        """isp | content | enterprise | other | unknown"""
        if not net:
            return "unknown"
        types = {t for t in (net.get("info_types") or []) if t}
        if not types and net.get("info_type"):
            types = {net["info_type"]}
        if types & ISP_TYPES:
            return "isp"
        if types & CONTENT_TYPES:
            return "content"
        if "Enterprise" in types:
            return "enterprise"
        return "other" if types else "unknown"


__all__ = ["PeeringDbClient", "HttpError"]
