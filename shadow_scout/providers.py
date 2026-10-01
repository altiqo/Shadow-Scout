"""Загрузка базы провайдеров (ручная + автокаталог + пользовательская), страны, фильтрация."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from shadow_scout.harvest.catalog_io import CATALOG_FILE, read_catalog, user_catalog_file
from shadow_scout.models import SIZE_ORDER, Provider, SearchQuery
from shadow_scout.paths import DATA_DIR, user_providers_file

_YamlLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # C-загрузчик в разы быстрее на больших файлах


def load_yaml(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_YamlLoader)


@dataclass(frozen=True)
class Country:
    code: str
    name_ru: str
    name_en: str
    region: str
    radar: str

    def label(self, lang: str = "ru") -> str:
        name = self.name_ru if lang == "ru" else self.name_en
        return f"{name} ({self.code})"


class CountryTable:
    def __init__(self, countries: dict[str, Country], radar_risk: dict[str, float]) -> None:
        self.countries = countries
        self.radar_risk = radar_risk

    def get(self, code: str) -> Country:
        code = code.upper()
        return self.countries.get(code) or Country(code, code, code, "—", "unknown")

    def name(self, code: str, lang: str = "ru") -> str:
        country = self.get(code)
        return country.name_ru if lang == "ru" else country.name_en

    def risk(self, code: str) -> float:
        return self.radar_risk.get(self.get(code).radar, self.radar_risk.get("unknown", 0.4))

    def by_region(self) -> dict[str, list[Country]]:
        groups: dict[str, list[Country]] = {}
        for country in self.countries.values():
            groups.setdefault(country.region, []).append(country)
        for items in groups.values():
            items.sort(key=lambda c: c.name_ru)
        return groups

    def low_radar_codes(self) -> list[str]:
        return [c.code for c in self.countries.values() if c.radar == "low"]


@lru_cache(maxsize=1)
def load_countries() -> CountryTable:
    raw = load_yaml(DATA_DIR / "countries.yaml") or {}
    countries = {
        code.upper(): Country(
            code=code.upper(),
            name_ru=str(item.get("name_ru", code)),
            name_en=str(item.get("name_en", code)),
            region=str(item.get("region", "—")),
            radar=str(item.get("radar", "unknown")),
        )
        for code, item in ((("NO" if c is False else str(c)), v) for c, v in (raw.get("countries") or {}).items())
    }
    radar_risk = {str(k): float(v) for k, v in (raw.get("radar_risk") or {}).items()}
    return CountryTable(countries, radar_risk)


def _parse_providers(raw: Any, source: str) -> list[Provider]:
    items = raw.get("providers") if isinstance(raw, dict) else raw
    out: list[Provider] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        item = dict(item)
        item.setdefault("source", source)
        try:
            provider = Provider.model_validate(item)
        except Exception as exc:  # noqa: BLE001 — одна битая запись не должна ломать базу
            print(f"[providers] пропущена запись {item.get('id')!r}: {exc}")
            continue
        if provider.vps is None and source in ("bundled", "user") and "discovered" not in provider.tags:
            provider.vps = True  # вручную добавленные записи — это VPS-провайдеры (кандидаты discovery — нет: это могут быть просто ISP)
        out.append(provider)
    return out


def _load_catalog() -> list[Provider]:
    """Поставляемый каталог + собранный пользователем (его записи заменяют поставляемые с теми же ASN)."""
    base = _parse_providers(read_catalog(CATALOG_FILE)[1], "catalog")
    mine = _parse_providers(read_catalog(user_catalog_file())[1], "catalog")
    if not mine:
        return base
    mine_asns = {a for p in mine for a in p.asns}
    mine_ids = {p.id for p in mine}
    return [p for p in base if p.id not in mine_ids and not (set(p.asns) & mine_asns)] + mine


class ProviderDB:
    def __init__(self, include_catalog: bool = True) -> None:
        self.include_catalog = include_catalog
        self.bundled: list[Provider] = []
        self.catalog: list[Provider] = []
        self.user: list[Provider] = []
        self.disabled_ids: set[str] = set()
        self._merged: list[Provider] | None = None
        self.reload()

    def reload(self) -> None:
        self._merged = None
        self.bundled = _parse_providers(load_yaml(DATA_DIR / "providers.yaml") or {}, "bundled")
        self.catalog = _load_catalog() if self.include_catalog else []
        self.user = []
        self.disabled_ids = set()
        path = user_providers_file()
        if path.exists():
            try:
                user_raw = load_yaml(path) or {}
            except yaml.YAMLError:
                user_raw = {}
            self.user = _parse_providers(user_raw, "user")
            self.disabled_ids = {str(x) for x in (user_raw.get("disabled") or [])} if isinstance(user_raw, dict) else set()

    def save_user(self) -> None:
        self._merged = None
        path = user_providers_file()
        payload = {
            "providers": [p.model_dump(mode="json", exclude={"source"}) for p in self.user],
            "disabled": sorted(self.disabled_ids),
        }
        path.write_text(
            "# Пользовательские провайдеры Shadow Scout (переопределяют встроенные с тем же id).\n"
            + yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    def _merge(self) -> list[Provider]:
        """Приоритет: пользовательские > ручная база > автокаталог; дубли каталога убираются по id, ASN и домену сайта."""
        manual = {p.id: p for p in self.bundled}
        manual.update({p.id: p for p in self.user})
        manual_asns = {a for p in manual.values() for a in p.asns}
        manual_domains = {d for p in manual.values() if (d := p.site_key())}
        merged = {
            p.id: p
            for p in self.catalog
            if p.id not in manual and not (set(p.asns) & manual_asns) and p.site_key() not in manual_domains
        }
        merged.update(manual)
        return sorted(merged.values(), key=lambda p: (p.name.casefold(), p.id))

    def all(self, include_disabled: bool = False) -> list[Provider]:
        if self._merged is None:
            self._merged = self._merge()
        if include_disabled:
            return list(self._merged)
        return [p for p in self._merged if p.enabled and p.id not in self.disabled_ids]

    def get(self, provider_id: str) -> Provider | None:
        for p in self.all(include_disabled=True):
            if p.id == provider_id:
                return p
        return None

    def add_user(self, provider: Provider) -> None:
        provider.source = "user"
        if provider.vps is None and "discovered" not in provider.tags:
            provider.vps = True
        self.user = [p for p in self.user if p.id != provider.id] + [provider]
        self.save_user()

    def remove_user(self, provider_id: str) -> bool:
        before = len(self.user)
        self.user = [p for p in self.user if p.id != provider_id]
        if len(self.user) != before:
            self.save_user()
            return True
        return False

    def set_disabled(self, provider_id: str, disabled: bool) -> None:
        if disabled:
            self.disabled_ids.add(provider_id)
        else:
            self.disabled_ids.discard(provider_id)
        self.save_user()

    def filter(self, query: SearchQuery) -> list[Provider]:
        providers = [p for p in self.all() if p.vps is not False]
        if not query.use_catalog:
            providers = [p for p in providers if p.source != "catalog"]
        if not query.include_unverified:
            providers = [p for p in providers if p.vps is True]
        if query.provider_ids:
            wanted = set(query.provider_ids)
            providers = [p for p in providers if p.id in wanted]
        if query.countries:
            wanted_cc = {c.upper() for c in query.countries}
            providers = [p for p in providers if wanted_cc & set(p.location_countries)]
        if query.require_trial:
            providers = [p for p in providers if _flag_ok(p.trial, query.strict_flags)]
        if query.require_hourly:
            providers = [p for p in providers if _flag_ok(p.hourly, query.strict_flags)]
        if query.max_price_eur is not None:
            providers = [p for p in providers if p.min_price_eur is None or p.min_price_eur <= query.max_price_eur]
        if query.ip_type:
            wanted_types = set(query.ip_type)
            providers = [p for p in providers if p.ip_type in wanted_types or p.ip_type == "unknown"]
        if query.max_size:
            limit = SIZE_ORDER.get(query.max_size, 4)
            providers = [p for p in providers if SIZE_ORDER.get(p.size, 1) <= limit]
        if not query.include_ru_ties:
            providers = [p for p in providers if not p.ru_ties and not p.rkn_hoster_registry]
        if query.tags:
            wanted_tags = set(query.tags)
            providers = [p for p in providers if wanted_tags & set(p.tags)]
        return providers

    def tags(self) -> list[str]:
        tags: set[str] = set()
        for p in self.all(include_disabled=True):
            tags.update(p.tags)
        return sorted(tags)

    def country_stats(self, query: SearchQuery | None = None) -> dict[str, dict[str, int]]:
        """По странам: сколько провайдеров можно арендовать (all), из них ручных (curated), каталога (catalog), местных (local)."""
        providers = self.filter(query) if query else self.all()
        stats: dict[str, dict[str, int]] = defaultdict(lambda: {"all": 0, "curated": 0, "catalog": 0, "local": 0})
        for p in providers:
            for cc in p.location_countries:
                row = stats[cc]
                row["all"] += 1
                row["catalog" if p.source == "catalog" else "curated"] += 1
                if p.hq_country == cc:
                    row["local"] += 1
        return dict(stats)


def _flag_ok(value: bool | None, strict: bool) -> bool:
    """trial/почасовая: строго — только подтверждённые, мягко — «неизвестно» тоже подходит (только явное «нет» отсекается)."""
    return value is True if strict else value is not False
