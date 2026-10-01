"""Модели данных: провайдеры, ASN, сигналы риска, отчёты."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

IpType = Literal["dch", "isp", "mixed", "unknown"]
ProviderSize = Literal["micro", "small", "medium", "large", "hyperscale"]
Verdict = Literal["low", "moderate", "high", "critical", "unknown"]

SIZE_ORDER: dict[str, int] = {"micro": 0, "small": 1, "medium": 2, "large": 3, "hyperscale": 4}


_SECOND_LEVEL_ZONES = {"co", "com", "org", "net", "ac", "edu", "gov", "ne", "or"}


def registrable_domain(host: str | None) -> str | None:
    """Домен второго уровня: staff.aruba.it → aruba.it, www.host.co.uk → host.co.uk. По нему сравниваем сайты провайдеров."""
    if not host:
        return None
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL_ZONES and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _country_code(value: object) -> str:
    # YAML 1.1 превращает NO/ON/OFF/YES в bool — восстанавливаем код Норвегии
    if value is False:
        return "NO"
    if value is True:
        return "ON"
    return str(value).strip().upper()


class Location(BaseModel):
    country: str
    city: str | None = None

    @field_validator("country", mode="before")
    @classmethod
    def _upper(cls, v: object) -> str:
        return _country_code(v)

    def label(self) -> str:
        return f"{self.country}-{self.city}" if self.city else self.country


class Provider(BaseModel):
    id: str
    name: str
    website: str | None = None
    asns: list[int] = Field(default_factory=list)
    asn_search: str | None = None
    aliases: list[str] = Field(default_factory=list)  # прежние/другие названия (для сверки с держателем ASN)
    hq_country: str = "ZZ"
    locations: list[Location] = Field(default_factory=list)
    size: ProviderSize = "small"
    popularity_ru: int = 2  # 1 — почти неизвестен в RU, 5 — массово используется
    ip_type: IpType = "dch"
    trial: bool | None = None
    trial_note: str | None = None
    hourly: bool | None = None
    min_price_eur: float | None = None
    payment: list[str] = Field(default_factory=list)
    ru_ties: bool = False
    rkn_hoster_registry: bool = False
    b2b_focus: bool = False
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    source: str = "bundled"  # bundled | catalog | user | discovered | adhoc
    enabled: bool = True
    # продаёт ли VPS/облачные серверы: True — подтверждено, None — не проверено, False — нет
    vps: bool | None = None
    # снимок PeeringDB на момент сборки каталога (избавляет от запросов при анализе)
    pdb_types: list[str] = Field(default_factory=list)
    pdb_traffic: str | None = None

    @field_validator("hq_country", mode="before")
    @classmethod
    def _upper(cls, v: object) -> str:
        return _country_code(v)

    @field_validator("id", mode="before")
    @classmethod
    def _id_str(cls, v: object) -> str:
        return str(v).strip()

    @property
    def countries(self) -> list[str]:
        seen: list[str] = []
        for loc in self.locations:
            if loc.country not in seen:
                seen.append(loc.country)
        if self.hq_country not in seen and self.hq_country != "ZZ":
            seen.append(self.hq_country)
        return seen

    @property
    def location_countries(self) -> list[str]:
        """Страны, где можно арендовать сервер: по списку локаций; без локаций — страна HQ."""
        seen = list(dict.fromkeys(loc.country for loc in self.locations))
        if not seen and self.hq_country != "ZZ":
            seen.append(self.hq_country)
        return seen

    @property
    def hints_only(self) -> bool:
        """Условия (trial / почасовая) определены автоматически и не проверялись вручную."""
        return self.source == "catalog"

    def locations_in(self, countries: list[str]) -> list[Location]:
        wanted = {c.upper() for c in countries}
        return [loc for loc in self.locations if loc.country in wanted]

    def website_domain(self) -> str | None:
        if not self.website:
            return None
        host = self.website.split("://", 1)[-1].split("/", 1)[0]
        return host.lower().removeprefix("www.")

    def site_key(self) -> str | None:
        """Регистрируемый домен сайта (без поддоменов) — ключ для поиска дублей."""
        return registrable_domain(self.website_domain())


class SignalStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class Signal(BaseModel):
    key: str
    title: str
    weight: float
    risk: float | None = None  # 0.0 (безопасно) .. 1.0 (максимальный риск)
    status: SignalStatus = SignalStatus.OK
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.risk is None:
            return "unknown"
        if self.risk < 0.2:
            return "low"
        if self.risk < 0.5:
            return "moderate"
        if self.risk < 0.8:
            return "high"
        return "critical"


class AsnInfo(BaseModel):
    asn: int
    holder: str | None = None
    country: str | None = None
    prefixes_v4: list[str] = Field(default_factory=list)
    prefixes_v6: list[str] = Field(default_factory=list)
    ipv4_count: int = 0
    blocked_prefixes: list[str] = Field(default_factory=list)
    blocked_ipv4_count: int = 0
    blocked_share: float = 0.0
    cdn_prefixes: list[str] = Field(default_factory=list)
    prefix_source: str = "unknown"
    peeringdb: dict[str, Any] | None = None
    holder_matches_provider: bool | None = None


class RiskReport(BaseModel):
    provider: Provider
    asns: list[AsnInfo] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    risk_score: float = 0.0
    survivability: float = 0.0
    confidence: float = 0.0
    verdict: Verdict = "unknown"
    hard_flags: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    matched_locations: list[Location] = Field(default_factory=list)
    # quick — только локальные данные (префиксы, списки блокировок); full — плюс cheburcheck, ip-api, пробы
    depth: Literal["quick", "full"] = "full"

    def signal(self, key: str) -> Signal | None:
        for s in self.signals:
            if s.key == key:
                return s
        return None

    @property
    def total_ipv4(self) -> int:
        return sum(a.ipv4_count for a in self.asns)

    @property
    def total_blocked_ipv4(self) -> int:
        return sum(a.blocked_ipv4_count for a in self.asns)

    @property
    def blocked_share(self) -> float:
        total = self.total_ipv4
        return (self.total_blocked_ipv4 / total) if total else 0.0


class SearchQuery(BaseModel):
    countries: list[str] = Field(default_factory=list)
    require_trial: bool = False
    require_hourly: bool = False
    max_price_eur: float | None = None
    ip_type: list[str] = Field(default_factory=list)  # пусто — любой
    max_asn_ipv4: int | None = None
    max_size: ProviderSize | None = None
    max_risk: Verdict | None = None  # отсечь всё хуже этого вердикта
    include_ru_ties: bool = False
    live_probe: bool = False
    limit: int = 200  # общий потолок числа анализируемых провайдеров (делится между локациями поровну)
    tags: list[str] = Field(default_factory=list)
    provider_ids: list[str] = Field(default_factory=list)
    # ── отбор по локациям ──
    per_location: int = 5  # сколько провайдеров показать на каждую локацию
    deep_per_location: int = 3  # у скольких лучших на локацию делать полную проверку (cheburcheck и др.); 0 — только быстрая
    group_by: Literal["country", "city"] = "country"
    max_repeat: int = 1  # в скольких локациях один провайдер может быть в «лучших» (0 — без ограничения)
    strict_flags: bool = False  # trial/почасовая: только подтверждённые (иначе «неизвестно» тоже подходит)
    include_unverified: bool = True  # провайдеры из каталога без подтверждённого VPS
    use_catalog: bool = True  # автоматически собранный каталог (PeeringDB) помимо ручной базы

    def describe(self) -> str:
        parts: list[str] = []
        if self.countries:
            parts.append("страны: " + ", ".join(self.countries))
        if self.require_trial:
            parts.append("нужен trial" + (" (строго)" if self.strict_flags else ""))
        if self.require_hourly:
            parts.append("почасовая оплата" + (" (строго)" if self.strict_flags else ""))
        if self.max_price_eur is not None:
            parts.append(f"≤ {self.max_price_eur:g} €/мес")
        if self.ip_type:
            parts.append("тип IP: " + "/".join(self.ip_type))
        if self.max_asn_ipv4:
            parts.append(f"ASN ≤ {self.max_asn_ipv4:,} IPv4".replace(",", " "))
        if self.max_size:
            parts.append(f"размер ≤ {self.max_size}")
        if self.max_risk:
            parts.append(f"риск ≤ {self.max_risk}")
        return "; ".join(parts) if parts else "без фильтров"


class SourceStatus(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class LocationPick(BaseModel):
    """Лучшие провайдеры для одной локации (страна или страна/город)."""

    country: str
    city: str | None = None
    provider_ids: list[str] = Field(default_factory=list)  # по убыванию «оценки подбора»
    candidates: int = 0  # сколько провайдеров из базы подошло под локацию и фильтры
    analyzed: int = 0  # сколько из них реально проанализировано

    @property
    def key(self) -> str:
        return f"{self.country}/{self.city}" if self.city else self.country


class SearchResult(BaseModel):
    query: SearchQuery
    reports: list[RiskReport] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    title: str = "Отчёт Shadow Scout"
    picks: list[LocationPick] = Field(default_factory=list)
    candidates_total: int = 0  # сколько провайдеров из базы подошло под фильтры
    candidates_analyzed: int = 0

    def report_by_id(self, provider_id: str) -> RiskReport | None:
        for r in self.reports:
            if r.provider.id == provider_id:
                return r
        return None

    def sorted_reports(self) -> list[RiskReport]:
        # Провайдеры без данных (unknown) — всегда внизу, остальные по выживаемости и уверенности
        return sorted(self.reports, key=lambda r: (r.verdict == "unknown", -r.survivability, -r.confidence, r.provider.name.lower()))


VERDICT_LABELS_RU: dict[str, str] = {
    "low": "Низкий риск",
    "moderate": "Умеренный риск",
    "high": "Высокий риск",
    "critical": "Критический риск",
    "unknown": "Нет данных",
}

VERDICT_LABELS_EN: dict[str, str] = {
    "low": "Low risk",
    "moderate": "Moderate risk",
    "high": "High risk",
    "critical": "Critical risk",
    "unknown": "No data",
}

VERDICT_COLORS: dict[str, str] = {
    "low": "#22c55e",
    "moderate": "#eab308",
    "high": "#f97316",
    "critical": "#ef4444",
    "unknown": "#94a3b8",
}
