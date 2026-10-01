"""Проверки с реальной сетью: формат внешних API, на которых держится сбор каталога и анализ.

Запуск: ``pytest -m network``. По умолчанию пропускаются (см. addopts в pyproject.toml): сеть нестабильна, а цель —
вовремя заметить, что PeeringDB / RIPEstat / ipverse поменяли формат ответа и харвестер молча начал отдавать мусор.
"""

from __future__ import annotations

import httpx
import pytest

from shadow_scout.harvest.peeringdb_dump import NET_FIELDS, NETFAC_FIELDS, ORG_FIELDS

pytestmark = pytest.mark.network

HEADERS = {"User-Agent": "ShadowScout-tests/1.0"}


def get(url: str, **params) -> httpx.Response:
    response = httpx.get(url, params=params, headers=HEADERS, timeout=60, follow_redirects=True)
    response.raise_for_status()
    return response


@pytest.mark.parametrize(("table", "fields"), [("net", NET_FIELDS), ("org", ORG_FIELDS), ("netfac", NETFAC_FIELDS)])
def test_peeringdb_dump_fields_exist(table, fields):
    data = get(f"https://www.peeringdb.com/api/{table}", depth=0, fields=fields, limit=3).json()["data"]
    assert data, table
    missing = set(fields.split(",")) - set(data[0])
    assert not missing, f"PeeringDB /{table} больше не отдаёт поля {missing} — обновите harvest/peeringdb_dump.py"


def test_peeringdb_net_by_asn_shape():
    net = get("https://www.peeringdb.com/api/net", asn=39122).json()["data"][0]  # Blacknight
    assert net["name"] and net["asn"] == 39122 and isinstance(net.get("info_types"), list)


def test_ipverse_prefix_file_format():
    text = get("https://raw.githubusercontent.com/ipverse/asn-ip/master/as/39122/ipv4-aggregated.txt").text
    prefixes = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert prefixes and all("/" in p for p in prefixes)


def test_ipverse_names_table_header():
    text = get("https://raw.githubusercontent.com/ipverse/asn-info/master/as.csv").text
    assert text.splitlines()[0].split(",") == ["asn", "handle", "description", "country-code"]


def test_ripestat_endpoints_used_by_the_tool():
    base = "https://stat.ripe.net/data"
    overview = get(f"{base}/as-overview/data.json", resource="AS39122", sourceapp="shadow-scout-tests").json()["data"]
    assert overview["announced"] is True and overview["holder"]
    abuse = get(f"{base}/abuse-contact-finder/data.json", resource="AS39122", sourceapp="shadow-scout-tests").json()["data"]
    assert any("@" in c for c in abuse["abuse_contacts"])
    network = get(f"{base}/network-info/data.json", resource="1.1.1.1", sourceapp="shadow-scout-tests").json()["data"]
    assert "13335" in [str(a) for a in network["asns"]]


def test_antifilter_lists_are_cidr_lines():
    text = get("https://antifilter.download/list/subnet.lst").text
    lines = [line for line in text.splitlines()[:50] if line.strip()]
    assert lines and all("/" in line for line in lines)


def test_cheburcheck_status_shape():
    status = get("https://cheburcheck.ru/api/v1/status").json()
    assert {"domain_count", "v4_count"} <= set(status)
