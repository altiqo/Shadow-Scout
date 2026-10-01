"""Проверка базы провайдеров против живых данных (ASN, держатель, размер, сайт, условия)."""

from __future__ import annotations

import httpx
from conftest import site_handler
from typer.testing import CliRunner

from shadow_scout.analysis.dbcheck import check_database, check_provider
from shadow_scout.cache import DiskCache
from shadow_scout.cli import app
from shadow_scout.harvest.webscan import WebScan
from shadow_scout.models import Location, Provider


def prov(**kw) -> Provider:
    base = dict(id="glesys", name="GleSYS", website="https://glesys.com", asns=[42708], hq_country="SE", locations=[Location(country="SE")], size="small", vps=True)
    base.update(kw)
    return Provider(**base)


def codes(issues) -> set[str]:
    return {i.code for i in issues}


async def test_healthy_record_has_no_issues(services):
    assert await check_provider(services, prov()) == []


async def test_asn_that_is_not_announced_is_an_error(services):
    issues = await check_provider(services, prov(asns=[4242424]))  # такого ASN нет в BGP
    assert "asn-not-announced" in codes(issues)
    assert next(i for i in issues if i.code == "asn-not-announced").level == "error"


async def test_search_only_records_get_a_fix_suggestion(services):
    issues = await check_provider(services, prov(asns=[], asn_search="Hostup", name="Hostup", website="https://hostup.se"))
    fix = next(i for i in issues if i.code == "asn-by-search")
    assert fix.level == "warn" and "asns: [12345]" in fix.message


async def test_unresolvable_asn_is_an_error(services):
    issues = await check_provider(services, prov(asns=[], asn_search="Nonexistent Corp", name="Nonexistent Corp", website=None))
    assert "asn-unresolved" in codes(issues)
    assert "no-asn" in codes(await check_provider(services, prov(asns=[], asn_search=None)))


async def test_holder_mismatch_and_aliases(services):
    wrong = await check_provider(services, prov(name="Somebody Else", website="https://elsewhere.example"))
    assert "holder-mismatch" in codes(wrong)
    # переименованный бренд: держатель в RIPE назван иначе — алиас снимает ложное срабатывание
    assert "holder-mismatch" not in codes(await check_provider(services, prov(name="Somebody Else", website="https://elsewhere.example", aliases=["GLESYS"])))


async def test_size_class_must_match_prefixes(services):
    issues = await check_provider(services, prov(size="hyperscale"))  # у GleSYS ~16k адресов
    assert "size-mismatch" in codes(issues)
    assert "size-mismatch" not in codes(await check_provider(services, prov(size="medium")))


async def test_unknown_country_is_reported(services):
    issues = await check_provider(services, prov(hq_country="QQ", locations=[Location(country="QQ")]))
    assert any(i.code == "unknown-country" and i.level == "info" for i in issues)


async def test_site_findings(services):
    dead = WebScan(url="https://x", fetched=False, error="сайт недоступен")
    assert "site-unreachable" in codes(await check_provider(services, prov(), dead))
    hourly = WebScan(url="https://x", fetched=True, vps=True, hosting=True, hourly=True, hourly_evidence="billed hourly")
    issues = await check_provider(services, prov(hourly=False), hourly)
    conflict = next(i for i in issues if i.code == "hourly-conflict")
    assert "billed hourly" in conflict.message  # цитата со страницы — чтобы человек проверил
    assert "hourly-unconfirmed" in codes(await check_provider(services, prov(hourly=True), WebScan(url="x", fetched=True, vps=True, hosting=True)))
    assert "no-vps-evidence" in codes(await check_provider(services, prov(), WebScan(url="x", fetched=True, hosting=True)))
    russian = WebScan(url="x", fetched=True, vps=True, hosting=True, russian=True)
    assert "ru-ties-missing" in codes(await check_provider(services, prov(), russian))
    assert "ru-ties-missing" not in codes(await check_provider(services, prov(ru_ties=True), russian))
    # кириллица без русского языка (болгарский и т. п.) — не повод подозревать связи с РФ
    assert "ru-ties-missing" not in codes(await check_provider(services, prov(), WebScan(url="x", fetched=True, vps=True, hosting=True, cyrillic=True)))


async def test_catalog_entries_are_not_blamed_for_missing_vps_evidence(services):
    entry = prov(source="catalog", vps=None)
    assert "no-vps-evidence" not in codes(await check_provider(services, entry, WebScan(url="x", fetched=True, hosting=True)))


async def test_check_database_sorts_errors_first_and_survives_failures(services, tmp_path, monkeypatch):
    providers = [prov(), prov(id="ghost", name="Ghost", asns=[4242424], website="https://nordicvps.example"), prov(id="boom", name="Boom")]
    from shadow_scout.analysis import dbcheck

    original = dbcheck.check_provider

    async def flaky(services_, provider, scan=None):
        if provider.id == "boom":
            raise RuntimeError("kaboom")
        return await original(services_, provider, scan)

    monkeypatch.setattr(dbcheck, "check_provider", flaky)
    progress: list[tuple[int, int]] = []
    issues = await check_database(
        services, providers, transport=httpx.MockTransport(site_handler), web_cache=DiskCache("webscan", tmp_path),
        progress=lambda done, total: progress.append((done, total)),
    )
    assert issues[0].level == "error"  # ошибки в начале списка
    assert any(i.provider_id == "boom" and i.code == "check-failed" and "kaboom" in i.message for i in issues)
    assert progress[-1] == (3, 3)
    no_web = await check_database(services, [prov()], web=False)
    assert no_web == []


def test_cli_verify_db_exit_code_reflects_errors(patched_services, tmp_path):
    # в мок-API нет почти ни одного реального ASN из ручной базы → ошибки → код 1; JSON сохраняется
    out = tmp_path / "issues.json"
    bad = CliRunner().invoke(app, ["verify-db", "--source", "curated", "-c", "SE", "--no-web", "--json", str(out), "--quiet"])
    assert bad.exit_code == 1 and out.exists() and "ошибок" in bad.output
    clean = CliRunner().invoke(app, ["verify-db", "--source", "user", "--no-web", "--quiet"])
    assert clean.exit_code == 0 and "Проверено записей: 0" in clean.output
    assert CliRunner().invoke(app, ["verify-db", "--source", "bogus"]).exit_code != 0
    assert CliRunner().invoke(app, ["verify-db", "--level", "bogus"]).exit_code != 0
