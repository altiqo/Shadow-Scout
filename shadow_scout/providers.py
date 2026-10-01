"""Загрузка базы провайдеров (встроенная + пользовательская), страны, фильтрация."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from shadow_scout.models import SIZE_ORDER, Provider, SearchQuery
from shadow_scout.paths import DATA_DIR, user_providers_file


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
    raw = yaml.safe_load((DATA_DIR / "countries.yaml").read_text(encoding="utf-8")) or {}
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
            out.append(Provider.model_validate(item))
        except Exception as exc:  # noqa: BLE001 — одна битая запись не должна ломать базу
            print(f"[providers] пропущена запись {item.get('id')!r}: {exc}")
    return out


class ProviderDB:
    def __init__(self) -> None:
        self.bundled: list[Provider] = []
        self.user: list[Provider] = []
        self.disabled_ids: set[str] = set()
        self.reload()

    def reload(self) -> None:
        bundled_raw = yaml.safe_load((DATA_DIR / "providers.yaml").read_text(encoding="utf-8")) or {}
        self.bundled = _parse_providers(bundled_raw, "bundled")
        self.user = []
        self.disabled_ids = set()
        path = user_providers_file()
        if path.exists():
            try:
                user_raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                user_raw = {}
            self.user = _parse_providers(user_raw, "user")
            self.disabled_ids = {str(x) for x in (user_raw.get("disabled") or [])} if isinstance(user_raw, dict) else set()

    def save_user(self) -> None:
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

    def all(self, include_disabled: bool = False) -> list[Provider]:
        merged: dict[str, Provider] = {p.id: p for p in self.bundled}
        for p in self.user:
            merged[p.id] = p
        providers = list(merged.values())
        if not include_disabled:
            providers = [p for p in providers if p.enabled and p.id not in self.disabled_ids]
        return sorted(providers, key=lambda p: p.name.lower())

    def get(self, provider_id: str) -> Provider | None:
        for p in self.all(include_disabled=True):
            if p.id == provider_id:
                return p
        return None

    def add_user(self, provider: Provider) -> None:
        provider.source = "user"
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
        providers = self.all()
        if query.provider_ids:
            wanted = set(query.provider_ids)
            providers = [p for p in providers if p.id in wanted]
        if query.countries:
            wanted_cc = {c.upper() for c in query.countries}
            providers = [p for p in providers if wanted_cc & set(p.countries)]
        if query.require_trial:
            providers = [p for p in providers if p.trial]
        if query.require_hourly:
            providers = [p for p in providers if p.hourly]
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
