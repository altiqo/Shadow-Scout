"""Массовая выгрузка PeeringDB (сети, организации, присутствие в ДЦ) с дисковым кешем."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from shadow_scout.cache import FileCache
from shadow_scout.config import Settings
from shadow_scout.net.http import HttpClient, HttpError

NET_FIELDS = "id,asn,name,aka,website,org_id,info_type,info_types,info_prefixes4,info_traffic,info_ratio,info_scope,status"
ORG_FIELDS = "id,name,aka,country,city,website,status"
NETFAC_FIELDS = "net_id,city,country,local_asn,status"


@dataclass
class PeeringDbDump:
    nets: list[dict[str, Any]] = field(default_factory=list)
    orgs: dict[int, dict[str, Any]] = field(default_factory=dict)
    netfacs: list[dict[str, Any]] = field(default_factory=list)

    def facilities_by_net(self) -> dict[int, list[dict[str, Any]]]:
        index: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for row in self.netfacs:
            if row.get("status", "ok") == "ok" and row.get("net_id") is not None:
                index[row["net_id"]].append(row)
        return index


async def _fetch_table(
    settings: Settings, http: HttpClient, cache: FileCache, table: str, fields: str, force: bool, log: Callable[[str], None] | None
) -> list[dict[str, Any]]:
    cfg = settings.sources.peeringdb
    url = f"{cfg.base_url.rstrip('/')}/{table}?depth=0&fields={fields}"
    ttl = settings.cache.peeringdb_ttl_hours * 3600
    text = None if force else cache.get(url, ttl)
    if text is None:
        if log:
            log(f"PeeringDB: загрузка таблицы {table}…")
        headers = {"Authorization": f"Api-Key {cfg.api_key}"} if cfg.api_key else None
        try:
            text = await http.get_text(url, source="peeringdb-dump", timeout=240, headers=headers)
        except HttpError:
            text = cache.get_stale(url)
            if text is None:
                raise
            if log:
                log(f"PeeringDB: {table} — сеть недоступна, используется устаревший кеш")
        else:
            cache.set(url, text)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise HttpError(f"PeeringDB {table}: некорректный JSON") from exc
    rows = data.get("data") if isinstance(data, dict) else None
    return rows if isinstance(rows, list) else []


async def load_dump(
    settings: Settings,
    http: HttpClient,
    *,
    cache: FileCache | None = None,
    force: bool = False,
    log: Callable[[str], None] | None = None,
) -> PeeringDbDump:
    if not settings.sources.peeringdb.enabled:
        raise HttpError("PeeringDB отключён в настройках — каталог собрать нельзя")
    cache = cache or FileCache("peeringdb-dump")
    nets = await _fetch_table(settings, http, cache, "net", NET_FIELDS, force, log)
    orgs = await _fetch_table(settings, http, cache, "org", ORG_FIELDS, force, log)
    netfacs = await _fetch_table(settings, http, cache, "netfac", NETFAC_FIELDS, force, log)
    dump = PeeringDbDump(
        nets=[n for n in nets if n.get("status", "ok") == "ok" and n.get("asn")],
        orgs={o["id"]: o for o in orgs if o.get("status", "ok") == "ok" and o.get("id") is not None},
        netfacs=netfacs,
    )
    if log:
        log(f"PeeringDB: {len(dump.nets)} сетей, {len(dump.orgs)} организаций, {len(dump.netfacs)} записей о присутствии в ДЦ")
    return dump
