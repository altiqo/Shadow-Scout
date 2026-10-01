"""Общий асинхронный HTTP-клиент: прокси, таймауты, ретраи, лимит частоты, кеш, учёт здоровья источников."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from shadow_scout.cache import DiskCache
from shadow_scout.config import NetworkSettings


class RateLimiter:
    """Простой лимитер «N запросов в минуту» для одного источника."""

    def __init__(self, per_minute: int) -> None:
        self.interval = 60.0 / max(1, per_minute)
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._next_at > now:
                await asyncio.sleep(self._next_at - now)
                now = time.monotonic()
            self._next_at = max(now, self._next_at) + self.interval


@dataclass
class SourceHealth:
    name: str
    ok_count: int = 0
    fail_count: int = 0
    last_error: str = ""
    disabled: bool = False

    @property
    def ok(self) -> bool:
        return not self.disabled and (self.ok_count > 0 or self.fail_count == 0)

    @property
    def detail(self) -> str:
        if self.disabled:
            return "отключён в настройках"
        if self.fail_count and not self.ok_count:
            return f"недоступен: {self.last_error}"[:120]
        if self.fail_count:
            return f"{self.ok_count} ok / {self.fail_count} ошибок"
        return f"{self.ok_count} запросов" if self.ok_count else "не использовался"


@dataclass
class HealthRegistry:
    sources: dict[str, SourceHealth] = field(default_factory=dict)

    def get(self, name: str) -> SourceHealth:
        if name not in self.sources:
            self.sources[name] = SourceHealth(name=name)
        return self.sources[name]

    def mark_ok(self, name: str) -> None:
        self.get(name).ok_count += 1

    def mark_fail(self, name: str, error: str) -> None:
        src = self.get(name)
        src.fail_count += 1
        src.last_error = error

    def mark_disabled(self, name: str) -> None:
        self.get(name).disabled = True


class HttpError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class HttpClient:
    def __init__(self, settings: NetworkSettings, health: HealthRegistry | None = None) -> None:
        self.settings = settings
        self.health = health or HealthRegistry()
        self._client: httpx.AsyncClient | None = None
        self._limiters: dict[str, RateLimiter] = {}
        self._transport: httpx.AsyncBaseTransport | None = None

    # для тестов: подмена транспорта
    def use_transport(self, transport: httpx.AsyncBaseTransport) -> None:
        self._transport = transport

    async def __aenter__(self) -> HttpClient:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is not None:
            return
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.settings.timeout_seconds),
            "headers": {"User-Agent": self.settings.user_agent, "Accept": "application/json, text/plain, */*"},
            "follow_redirects": True,
            "verify": self.settings.verify_tls,
        }
        if self.settings.proxy:
            kwargs["proxy"] = self.settings.proxy
        if self._transport is not None:
            kwargs["transport"] = self._transport
            kwargs.pop("proxy", None)
        self._client = httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def limiter(self, name: str, per_minute: int) -> RateLimiter:
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(per_minute)
        return self._limiters[name]

    async def request(
        self,
        method: str,
        url: str,
        *,
        source: str,
        per_minute: int | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        if self._client is None:
            await self.start()
        assert self._client is not None
        if per_minute:
            await self.limiter(source, per_minute).wait()
        last_error: Exception | None = None
        for attempt in range(self.settings.retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    json=json_body,
                    timeout=timeout or self.settings.timeout_seconds,
                )
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", "5") or 5)
                    await asyncio.sleep(min(retry_after, 30))
                    last_error = HttpError("429 Too Many Requests", 429)
                    continue
                if response.status_code >= 500:
                    last_error = HttpError(f"HTTP {response.status_code}", response.status_code)
                    await asyncio.sleep(0.8 * (attempt + 1))
                    continue
                self.health.mark_ok(source)
                return response
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = exc
                await asyncio.sleep(0.8 * (attempt + 1))
        message = str(last_error) if last_error else "unknown error"
        self.health.mark_fail(source, message)
        raise HttpError(message, getattr(last_error, "status", None))

    async def get_json(
        self,
        url: str,
        *,
        source: str,
        per_minute: int | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache: DiskCache | None = None,
        ttl_seconds: float | None = None,
        timeout: float | None = None,
    ) -> Any:
        cache_key = url + ("?" + json.dumps(params, sort_keys=True) if params else "")
        if cache is not None:
            cached = cache.get(cache_key, ttl_seconds)
            if cached is not None:
                return cached
        response = await self.request(
            "GET", url, source=source, per_minute=per_minute, params=params, headers=headers, timeout=timeout
        )
        if response.status_code >= 400:
            self.health.mark_fail(source, f"HTTP {response.status_code}")
            raise HttpError(f"HTTP {response.status_code} for {url}", response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            self.health.mark_fail(source, "invalid JSON")
            raise HttpError(f"invalid JSON from {url}") from exc
        if cache is not None:
            cache.set(cache_key, data)
        return data

    async def post_json(
        self,
        url: str,
        body: Any,
        *,
        source: str,
        per_minute: int | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        response = await self.request(
            "POST", url, source=source, per_minute=per_minute, json_body=body, headers=headers, timeout=timeout
        )
        if response.status_code >= 400:
            self.health.mark_fail(source, f"HTTP {response.status_code}")
            raise HttpError(f"HTTP {response.status_code} for {url}", response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}") from exc

    async def get_text(
        self,
        url: str,
        *,
        source: str,
        per_minute: int | None = None,
        timeout: float | None = None,
        max_bytes: int = 64 * 1024 * 1024,
    ) -> str:
        response = await self.request("GET", url, source=source, per_minute=per_minute, timeout=timeout)
        if response.status_code >= 400:
            self.health.mark_fail(source, f"HTTP {response.status_code}")
            raise HttpError(f"HTTP {response.status_code} for {url}", response.status_code)
        if len(response.content) > max_bytes:
            raise HttpError(f"response too large from {url}")
        return response.text
