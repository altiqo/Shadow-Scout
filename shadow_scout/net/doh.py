"""Разрешение имён через DNS-over-HTTPS (устойчиво к подмене DNS у провайдера) с запасным системным резолвером."""

from __future__ import annotations

import asyncio
import socket

from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError


class Resolver:
    def __init__(self, settings: Settings, http: HttpClient) -> None:
        self.settings = settings
        self.http = http
        self.name = "doh"

    async def resolve(self, hostname: str) -> list[str]:
        hostname = hostname.strip().lower().rstrip(".")
        if not hostname:
            return []
        for url in (self.settings.sources.fallback.doh_url, self.settings.sources.fallback.doh_fallback_url):
            try:
                data = await self.http.get_json(
                    url,
                    source=self.name,
                    params={"name": hostname, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                    timeout=10,
                )
            except HttpError:
                continue
            answers = data.get("Answer") if isinstance(data, dict) else None
            if answers:
                ips = [a.get("data") for a in answers if a.get("type") == 1 and a.get("data")]
                if ips:
                    return ips
        return await self._system_resolve(hostname)

    async def _system_resolve(self, hostname: str) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(hostname, 443, socket.AF_INET))
        except (socket.gaierror, OSError):
            return []
        ips: list[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
