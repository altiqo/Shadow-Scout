"""Общие фикстуры: мок-транспорт httpx, эмулирующий RIPEstat, PeeringDB, cheburcheck, ip-api и списки блокировок."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx
import pytest

# Изолируем конфиг/кеш тестов от пользовательских каталогов
_TMP = Path(os.environ.get("PYTEST_TMPDIR", "/tmp")) / "shadow-scout-tests"
os.environ.setdefault("SHADOW_SCOUT_CONFIG_DIR", str(_TMP / "config"))
os.environ.setdefault("SHADOW_SCOUT_CACHE_DIR", str(_TMP / "cache"))
os.environ.setdefault("SHADOW_SCOUT_DATA_DIR", str(_TMP / "data"))

BLOCKED_LIST = "\n".join([
    "5.9.0.0/16",          # Hetzner — большой блок
    "95.217.165.190/32",
    "185.100.86.0/24",     # FlokiNET-подобный пример
    "203.0.113.0/24",
])

CDN_CSV = "provider,cidr,region\ncloudflare,104.16.0.0/13,\nakamai,23.32.0.0/11,\n"

ASN_DATA: dict[int, dict] = {
    24940: {"holder": "HETZNER-AS", "prefixes": ["5.9.0.0/16", "95.217.0.0/16", "2a01:4f8::/29"]},
    42708: {"holder": "GLESYS-AS", "prefixes": ["46.21.96.0/20", "80.78.224.0/20"]},
    200651: {"holder": "FLOKINET", "prefixes": ["185.100.84.0/22", "185.246.188.0/22"]},
    202053: {"holder": "UPCLOUD", "prefixes": ["83.136.248.0/21", "94.237.0.0/17"]},
    99999: {"holder": "TINY-LOCAL-ISP", "prefixes": ["198.51.100.0/24"]},
}

PDB = {
    24940: {"name": "Hetzner Online", "info_types": ["Content"], "info_traffic": "5-10Tbps", "info_scope": "Global", "website": "https://www.hetzner.com"},
    42708: {"name": "GleSYS", "info_types": ["NSP"], "info_traffic": "100-200Gbps", "info_scope": "Regional", "website": "https://glesys.com"},
    99999: {"name": "Tiny ISP", "info_types": ["Cable/DSL/ISP"], "info_traffic": "1-5Gbps", "info_scope": "Regional", "website": "https://tiny.example"},
}

ASN_CSV = "asn,handle,description,country-code\n24940,HETZNER-AS,Hetzner Online GmbH,DE\n42708,GLESYS-AS,GleSYS AB,SE\n99999,TINY,Tiny Local ISP AB,SE\n200651,FLOKINET,FlokiNET ehf,IS\n12345,HOSTUP,Hostup AB,SE\n"


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.cheburcheck_down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        host = request.url.host
        path = request.url.path
        q = dict(request.url.params)
        if host == "stat.ripe.net":
            resource = q.get("resource", "")
            if "announced-prefixes" in path:
                asn = int(re.sub(r"\D", "", resource) or 0)
                data = ASN_DATA.get(asn)
                return httpx.Response(200, json={"status": "ok", "data": {"prefixes": [{"prefix": p} for p in (data or {}).get("prefixes", [])]}})
            if "as-overview" in path:
                asn = int(re.sub(r"\D", "", resource) or 0)
                data = ASN_DATA.get(asn)
                return httpx.Response(200, json={"status": "ok", "data": {"holder": (data or {}).get("holder"), "announced": bool(data)}})
            if "searchcomplete" in path:
                if resource.lower().startswith("hostup"):
                    return httpx.Response(200, json={"status": "ok", "data": {"categories": [{"category": "ASNs", "suggestions": [{"label": "AS12345", "value": "AS12345", "description": "HOSTUP-AS Hostup AB"}]}]}})
                return httpx.Response(200, json={"status": "ok", "data": {"categories": []}})
            if "country-asns" in path:
                return httpx.Response(200, json={"status": "ok", "data": {"countries": [{"resource": "se", "routed": ["AsnSingle(42708)", "AsnSingle(99999)"], "non_routed": []}]}})
            if "network-info" in path:
                return httpx.Response(200, json={"status": "ok", "data": {"asns": ["24940"], "prefix": "5.9.0.0/16"}})
            if "maxmind-geo-lite" in path:
                return httpx.Response(200, json={"status": "ok", "data": {"located_resources": [{"locations": [{"country": "DE", "city": "Falkenstein"}]}]}})
            return httpx.Response(404, json={"status": "error"})
        if host == "www.peeringdb.com":
            asn = int(q.get("asn", 0))
            net = PDB.get(asn)
            return httpx.Response(200, json={"data": [net] if net else []})
        if host == "cheburcheck.ru":
            if self.cheburcheck_down:
                return httpx.Response(503, text="down")
            if path.endswith("/status"):
                return httpx.Response(200, json={"domain_count": 100, "v4_count": 1000, "last_update": "2026-01-01", "version": "test"})
            target = q.get("target", "")
            m = re.fullmatch(r"(?i)AS(\d+)", target)
            if m:
                asn = int(m.group(1))
                data = ASN_DATA.get(asn)
                if not data:
                    return httpx.Response(404, json={"code": 404, "info": "Not Found"})
                prefixes = data["prefixes"]
                blocked = [p for p in prefixes if p.startswith("5.9.") or p.startswith("185.100.")]
                return httpx.Response(200, json={
                    "id": "x", "target": target, "target_type": "ASN", "blocked": bool(blocked), "ips": [], "reverse_lookup": [],
                    "blocked_subnets": blocked, "cdn_providers": {}, "geo": {"asn": f"AS{asn}", "country_code": "DE", "organisation": data["holder"], "location": "-"},
                    "asn_info": {"asn": asn, "prefixes": prefixes, "blocked_prefixes": blocked},
                    "complaints": [{"date": "2026-01-01", "count": 3 if blocked else 0}],
                })
            if target == "hetzner.com":
                return httpx.Response(200, json={"target": target, "target_type": "Domain", "blocked": False, "ips": ["213.133.116.46"], "reverse_lookup": [], "blocked_subnets": [], "cdn_providers": {}, "geo": {"location": "-"}, "complaints": []})
            if target == "blocked.example":
                return httpx.Response(200, json={"target": target, "target_type": "Domain", "blocked": True, "rkn_domain": "blocked.example", "ips": ["203.0.113.5"], "reverse_lookup": [], "blocked_subnets": ["203.0.113.0/24"], "cdn_providers": {}, "geo": {"location": "-"}, "complaints": []})
            return httpx.Response(200, json={"target": target, "target_type": "Domain", "blocked": False, "ips": ["198.51.100.10"], "reverse_lookup": [], "blocked_subnets": [], "cdn_providers": {}, "geo": {"location": "-"}, "complaints": []})
        if host == "ip-api.com":
            body = json.loads(request.content or b"[]")
            out = []
            for item in body:
                ip = item["query"]
                out.append({"status": "success", "query": ip, "countryCode": "SE", "isp": "x", "org": "y", "as": "AS1", "asname": "X", "hosting": not ip.startswith("198.51."), "proxy": False, "mobile": False})
            return httpx.Response(200, json=out)
        if host in ("cloudflare-dns.com", "dns.google"):
            name = q.get("name", "")
            return httpx.Response(200, json={"Status": 0, "Answer": [{"name": name, "type": 1, "data": "198.51.100.10"}]})
        if host == "raw.githubusercontent.com":
            if "Re-filter" in url:
                return httpx.Response(200, text=BLOCKED_LIST)
            if "cdn-ip-ranges" in url:
                return httpx.Response(200, text=CDN_CSV)
            if "asn-info" in url:
                return httpx.Response(200, text=ASN_CSV)
            if "asn-ip" in url:
                asn = int(re.search(r"/as/(\d+)/", url).group(1))
                data = ASN_DATA.get(asn)
                if not data:
                    return httpx.Response(404, text="nope")
                return httpx.Response(200, text="# AS\n" + "\n".join(p for p in data["prefixes"] if ":" not in p))
        if host in ("antifilter.network", "antifilter.download"):
            return httpx.Response(200, text=BLOCKED_LIST)
        return httpx.Response(404, text="unhandled " + url)


@pytest.fixture
def fake_api() -> FakeApi:
    return FakeApi()


@pytest.fixture
def settings(tmp_path):
    from shadow_scout.config import Settings

    s = Settings()
    s.general.export_dir = str(tmp_path / "reports")
    s.network.retries = 0
    s.network.concurrency = 4
    s.sources.cheburcheck.requests_per_minute = 6000
    s.sources.ripestat.requests_per_minute = 6000
    s.sources.peeringdb.requests_per_minute = 6000
    s.sources.ipapi.requests_per_minute = 6000
    s.live_probe.enabled = False
    return s


@pytest.fixture
def services(settings, fake_api, tmp_path):
    from shadow_scout.analysis.engine import Services
    from shadow_scout.cache import DiskCache, FileCache
    from shadow_scout.net.http import HealthRegistry, HttpClient

    http = HttpClient(settings.network, HealthRegistry())
    http.use_transport(httpx.MockTransport(fake_api.handler))
    svc = Services.build(settings, http)
    root = tmp_path / "cache"
    svc.ripe.cache = DiskCache("ripestat", root)
    svc.prefixes.cache = DiskCache("prefixes", root)
    svc.peeringdb.cache = DiskCache("peeringdb", root)
    svc.cheburcheck.cache = DiskCache("cheburcheck", root)
    svc.ipapi.cache = DiskCache("ipapi", root)
    svc.asn_resolve_cache = DiskCache("asn-resolve", root)
    svc.blocklists.cache = FileCache("blocklists", root)
    svc.asn_names.cache = FileCache("asn-names", root)
    return svc


@pytest.fixture
def patched_services(monkeypatch, settings, fake_api, tmp_path):
    import shadow_scout.config as config
    from shadow_scout import runner
    from shadow_scout.analysis.engine import Services
    from shadow_scout.cache import DiskCache, FileCache
    from shadow_scout.net.http import HealthRegistry, HttpClient

    def build(_settings):
        http = HttpClient(_settings.network, HealthRegistry())
        http.use_transport(httpx.MockTransport(fake_api.handler))
        svc = Services.build(_settings, http)
        root = tmp_path / "cache"
        svc.ripe.cache = DiskCache("ripestat", root)
        svc.prefixes.cache = DiskCache("prefixes", root)
        svc.peeringdb.cache = DiskCache("peeringdb", root)
        svc.cheburcheck.cache = DiskCache("cheburcheck", root)
        svc.ipapi.cache = DiskCache("ipapi", root)
        svc.asn_resolve_cache = DiskCache("asn-resolve", root)
        svc.blocklists.cache = FileCache("blocklists", root)
        svc.asn_names.cache = FileCache("asn-names", root)
        return svc

    monkeypatch.setattr(runner, "build_services", build)
    monkeypatch.setattr(config, "_settings", settings)
    monkeypatch.setattr(runner, "last_result_file", lambda: tmp_path / "last.json")
    return build


