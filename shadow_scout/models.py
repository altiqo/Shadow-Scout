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
    source: str = "bundled"
    enabled: bool = True

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

    def locations_in(self, countries: list[str]) -> list[Location]:
        wanted = {c.upper() for c in countries}
        return [loc for loc in self.locations if loc.country in wanted]

    def website_domain(self) -> str | None:
        if not self.website:
            return None
        host = self.website.split("://", 1)[-1].split("/", 1)[0]
        return host.lower().removeprefix("www.")


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
    limit: int = 25
    tags: list[str] = Field(default_factory=list)
    provider_ids: list[str] = Field(default_factory=list)

    def describe(self) -> str:
        parts: list[str] = []
        if self.countries:
            parts.append("страны: " + ", ".join(self.countries))
        if self.require_trial:
            parts.append("нужен trial")
        if self.require_hourly:
            parts.append("почасовая оплата")
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


class SearchResult(BaseModel):
    query: SearchQuery
    reports: list[RiskReport] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    title: str = "Отчёт Shadow Scout"

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
