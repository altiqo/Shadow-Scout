"""Живые TCP-пробы с машины пользователя: достижимость адресов провайдера (полезно из РФ)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from shadow_scout.config import LiveProbeSettings


@dataclass
class ProbeOutcome:
    ip: str
    port: int
    result: str  # open | refused | timeout | unreachable
    latency_ms: float | None


async def probe_one(ip: str, port: int, timeout: float) -> ProbeOutcome:
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ProbeOutcome(ip, port, "open", (loop.time() - start) * 1000)
    except asyncio.TimeoutError:
        return ProbeOutcome(ip, port, "timeout", None)
    except ConnectionRefusedError:
        return ProbeOutcome(ip, port, "refused", (loop.time() - start) * 1000)
    except OSError:
        return ProbeOutcome(ip, port, "unreachable", None)


async def probe_many(ips: list[str], cfg: LiveProbeSettings, concurrency: int = 16) -> list[ProbeOutcome]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(ip: str, port: int) -> ProbeOutcome:
        async with semaphore:
            return await probe_one(ip, port, cfg.timeout_seconds)

    tasks = [run(ip, port) for ip in ips for port in cfg.ports]
    return await asyncio.gather(*tasks)


async def control_reachable(cfg: LiveProbeSettings) -> bool:
    outcome = await probe_one(cfg.control_host, cfg.control_port, cfg.timeout_seconds)
    return outcome.result in ("open", "refused")
