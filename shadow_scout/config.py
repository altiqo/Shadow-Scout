"""Настройки приложения: модель, значения по умолчанию, загрузка и сохранение в YAML."""

from __future__ import annotations

from typing import Any

import yaml
from pydantic import BaseModel, Field

from shadow_scout.paths import config_file, default_reports_dir


class GeneralSettings(BaseModel):
    language: str = "ru"
    export_dir: str = str(default_reports_dir())
    default_exports: list[str] = Field(default_factory=lambda: ["html", "pdf"])
    per_location: int = 5  # сколько лучших провайдеров показывать на каждую локацию
    deep_per_location: int = 3  # у скольких лучших на локацию делать полную проверку (cheburcheck и др.)
    max_candidates: int = 200  # общий потолок числа анализируемых провайдеров за один поиск
    auto_update_lists_days: int = 1
    show_banner: bool = True


class NetworkSettings(BaseModel):
    proxy: str | None = None
    timeout_seconds: float = 20.0
    retries: int = 2
    concurrency: int = 6
    user_agent: str = "ShadowScout/1.0 (+https://github.com/altiqo/shadow-scout)"
    verify_tls: bool = True


class CheburcheckSettings(BaseModel):
    enabled: bool = True
    base_url: str = "https://cheburcheck.ru"
    requests_per_minute: int = 20
    check_website: bool = True
    check_asn: bool = True


class RipeStatSettings(BaseModel):
    enabled: bool = True
    base_url: str = "https://stat.ripe.net/data"
    requests_per_minute: int = 120


class PeeringDbSettings(BaseModel):
    enabled: bool = True
    base_url: str = "https://www.peeringdb.com/api"
    api_key: str | None = None
    requests_per_minute: int = 30


class IpApiSettings(BaseModel):
    enabled: bool = True
    base_url: str = "http://ip-api.com"
    samples_per_asn: int = 6
    requests_per_minute: int = 40


class BlocklistSource(BaseModel):
    name: str
    url: str
    kind: str = "cidr"  # cidr | cdn_csv
    enabled: bool = True
    weight: float = 1.0


DEFAULT_BLOCKLISTS: list[BlocklistSource] = [
    BlocklistSource(name="antifilter.network ipsum", url="https://antifilter.network/download/ipsum.lst"),
    BlocklistSource(name="antifilter.download subnet", url="https://antifilter.download/list/subnet.lst"),
    BlocklistSource(name="antifilter.download ip", url="https://antifilter.download/list/ip.lst", weight=0.7),
    BlocklistSource(
        name="Re:filter ipsum",
        url="https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst",
    ),
    BlocklistSource(
        name="CDN ranges (123jjck)",
        url="https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all.csv",
        kind="cdn_csv",
    ),
]


class FallbackSources(BaseModel):
    asn_prefixes_template: str = (
        "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{asn}/ipv4-aggregated.txt"
    )
    asn_names_csv: str = "https://raw.githubusercontent.com/ipverse/asn-info/master/as.csv"
    doh_url: str = "https://cloudflare-dns.com/dns-query"
    doh_fallback_url: str = "https://dns.google/resolve"


class SourcesSettings(BaseModel):
    cheburcheck: CheburcheckSettings = Field(default_factory=CheburcheckSettings)
    ripestat: RipeStatSettings = Field(default_factory=RipeStatSettings)
    peeringdb: PeeringDbSettings = Field(default_factory=PeeringDbSettings)
    ipapi: IpApiSettings = Field(default_factory=IpApiSettings)
    blocklists: list[BlocklistSource] = Field(default_factory=lambda: list(DEFAULT_BLOCKLISTS))
    fallback: FallbackSources = Field(default_factory=FallbackSources)


class ScoringWeights(BaseModel):
    blocklist_overlap: float = 3.0
    cheburcheck_asn: float = 3.0
    cheburcheck_site: float = 1.0
    asn_size: float = 1.5
    network_type: float = 1.5
    popularity: float = 1.5
    jurisdiction: float = 1.0
    cdn_membership: float = 1.0
    ru_ties: float = 2.0
    complaints: float = 1.0
    live_probe: float = 1.5
    asn_fragmentation: float = 0.5


class ScoringThresholds(BaseModel):
    low_max: float = 20.0
    moderate_max: float = 45.0
    high_max: float = 70.0
    hard_blocked_share: float = 0.5  # доля заблокированного адресного пространства -> критично
    small_asn_ipv4: int = 16384  # «маленькая» сеть по умолчанию (<= /18)
    max_asn_ipv4_default: int = 262144  # фильтр по умолчанию в мастере (<= /14)


class ScoringSettings(BaseModel):
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    thresholds: ScoringThresholds = Field(default_factory=ScoringThresholds)
    low_radar_countries: list[str] = Field(
        default_factory=lambda: ["SE", "HU", "IS", "FI", "NO", "DK", "EE", "LV", "LT", "CZ", "SK", "AT", "CH", "SI", "HR"]
    )


class LiveProbeSettings(BaseModel):
    enabled: bool = False
    ports: list[int] = Field(default_factory=lambda: [443, 22])
    timeout_seconds: float = 3.0
    samples_per_asn: int = 8
    control_host: str = "1.1.1.1"
    control_port: int = 443


class CacheSettings(BaseModel):
    blocklists_ttl_hours: int = 24
    ripestat_ttl_hours: int = 72
    peeringdb_ttl_hours: int = 168
    cheburcheck_ttl_hours: int = 12
    ipapi_ttl_hours: int = 168
    asn_names_ttl_hours: int = 168


class Settings(BaseModel):
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    sources: SourcesSettings = Field(default_factory=SourcesSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    live_probe: LiveProbeSettings = Field(default_factory=LiveProbeSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)

    # --- persistence -------------------------------------------------
    @classmethod
    def load(cls) -> Settings:
        path = config_file()
        if not path.exists():
            settings = cls()
            settings.save()
            return settings
        try:
            raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return cls.model_validate(raw)
        except Exception:
            # Повреждённый конфиг: не падаем, работаем на значениях по умолчанию
            backup = path.with_suffix(".broken.yaml")
            try:
                path.replace(backup)
            except OSError:
                pass
            settings = cls()
            settings.save()
            return settings

    def save(self) -> None:
        path = config_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        header = (
            "# Shadow Scout — файл настроек. Редактируйте вручную или через меню «Настройки».\n"
            "# Удалите файл, чтобы вернуть значения по умолчанию.\n"
        )
        path.write_text(header + yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")

    def reset_section(self, section: str) -> None:
        defaults = Settings()
        setattr(self, section, getattr(defaults, section))


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings


def set_settings(settings: Settings) -> None:
    global _settings
    _settings = settings
