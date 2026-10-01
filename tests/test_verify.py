"""Проверка конкретного IP: списки, подсеть, cheburcheck, живые пробы."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shadow_scout.analysis import verify as verify_mod
from shadow_scout.analysis.verify import parse_ip, subnet_of, verify_ip
from shadow_scout.cli import app
from shadow_scout.config import BlocklistSource
from shadow_scout.net.blocklists import BlocklistBundle, LoadedList
from shadow_scout.net.ipindex import NetworkSet
from shadow_scout.net.liveprobe import ProbeOutcome, TlsOutcome


def levels(report) -> set[str]:
    return {f.level for f in report.findings}


def custom_bundle(*cidrs: str) -> BlocklistBundle:
    nets = NetworkSet()
    nets.add_many(cidrs)
    return BlocklistBundle(lists=[LoadedList(BlocklistSource(name="test-list", url="x"), nets, nets.entries, 1.0, False)])


# ───────────────────────── разбор адреса ─────────────────────────
@pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "203.0.113.5", "999.1.1.1"])
def test_parse_ip_rejects_non_global_addresses(bad):
    with pytest.raises(ValueError):
        parse_ip(bad)


def test_parse_ip_normalizes_and_subnet():
    assert parse_ip("  1.1.1.1 ") == "1.1.1.1"
    assert parse_ip("2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111"
    assert subnet_of("46.21.96.10") == "46.21.96.0/24"
    assert subnet_of("2606:4700:4700::1111") == "2606:4700:4700::/64"


# ───────────────────────── вердикты ─────────────────────────
async def test_exact_ip_in_blocklist_is_blocked(services):
    report = await verify_ip(services, "95.217.165.190")
    assert report.verdict == "blocked" and report.lists_hit
    assert report.asn == 24940 and report.holder == "HETZNER-AS" and report.country == "DE"
    assert "bad" in levels(report) and "не платите" in report.recommendation


async def test_clean_ip_in_clean_network_is_ok(services):
    report = await verify_ip(services, "46.21.96.10")  # GleSYS: ни адреса, ни подсети, ни ASN в списках
    assert report.verdict == "ok" and not report.lists_hit and report.subnet_blocked_share == 0
    assert report.asn == 42708 and report.cheburcheck_blocked is False and report.hosting is True
    assert "bad" not in levels(report) and "warn" not in levels(report)


async def test_blocked_neighbours_in_subnet_make_it_risky(services):
    await services.ensure_blocklists()
    services.bundle = custom_bundle("45.45.45.0/27")  # 32 из 256 адресов подсети; сам адрес .200 чист
    report = await verify_ip(services, "45.45.45.200")
    assert report.verdict == "risk" and not report.lists_hit
    assert report.subnet_blocked_share == pytest.approx(32 / 256) and report.blocked_neighbours == ["45.45.45.0/27"]
    assert any("соседей по подсети" in f.text for f in report.findings)


async def test_few_blocked_neighbours_are_only_informational(services):
    await services.ensure_blocklists()
    services.bundle = custom_bundle("45.45.45.0/30")  # 4 адреса — меньше порога
    report = await verify_ip(services, "45.45.45.200")
    assert report.verdict == "ok" and any(f.level == "info" and "подсети" in f.text for f in report.findings)


async def test_heavily_blocked_asn_is_risky_even_for_clean_ip(services):
    report = await verify_ip(services, "5.9.200.1".replace("5.9.200.1", "95.217.1.1"))  # Hetzner: ASN на ~50% в списках
    assert report.asn_blocked_share and report.asn_blocked_share > 0.25
    assert report.verdict == "risk"


async def test_cheburcheck_flags_and_complaints(services, monkeypatch):
    async def fake_check(target):
        return {"blocked": True, "blocked_subnets": ["46.21.96.0/20"], "rkn_domain": None, "complaints_total": 4}

    monkeypatch.setattr(services.cheburcheck, "check", fake_check)
    report = await verify_ip(services, "46.21.96.10")
    assert report.verdict == "blocked" and report.cheburcheck_blocked and report.complaints == 4
    assert any("жалоб" in f.text for f in report.findings)


async def test_cheburcheck_outage_does_not_block_verdict(services, fake_api):
    fake_api.cheburcheck_down = True
    report = await verify_ip(services, "46.21.96.10")
    assert report.cheburcheck_blocked is None and report.verdict == "ok"
    assert any("cheburcheck недоступен" in f.text for f in report.findings)


async def test_without_any_source_verdict_is_unknown(services):
    await services.ensure_blocklists()
    services.bundle = BlocklistBundle()  # списки не загружены
    services.settings.sources.cheburcheck.enabled = False
    report = await verify_ip(services, "46.21.96.10")
    assert report.verdict == "unknown" and "не загружены" in report.findings[0].text


# ───────────────────────── живые пробы ─────────────────────────
def script_probes(monkeypatch, results: dict[int, str], control: bool = True):
    async def control_ok(cfg):
        return control

    async def probe(ip, port, timeout):
        return ProbeOutcome(ip, port, results.get(port, "timeout"), 12.5 if results.get(port) in ("open", "refused") else None)

    monkeypatch.setattr(verify_mod, "control_reachable", control_ok)
    monkeypatch.setattr(verify_mod, "probe_one", probe)


async def test_live_probe_reachable(services, monkeypatch):
    script_probes(monkeypatch, {22: "open", 443: "refused"})
    report = await verify_ip(services, "46.21.96.10", live=True)
    assert report.verdict == "ok" and [(p.port, p.result) for p in report.ports] == [(22, "open"), (443, "refused")]
    assert any("достижим" in f.text for f in report.findings)


async def test_live_probe_silence_is_a_risk(services, monkeypatch):
    script_probes(monkeypatch, {})
    report = await verify_ip(services, "46.21.96.10", live=True, ports=[22])
    assert report.verdict == "risk" and any("Ни один порт не ответил" in f.text for f in report.findings)


async def test_live_probe_skipped_when_control_host_down(services, monkeypatch):
    script_probes(monkeypatch, {}, control=False)
    report = await verify_ip(services, "46.21.96.10", live=True)
    assert report.control_ok is False and not report.ports and report.verdict == "ok"  # нет интернета ≠ заблокирован адрес
    assert any("Контрольный хост" in f.text for f in report.findings)


@pytest.mark.parametrize(("outcome", "verdict", "needle"), [
    (TlsOutcome("x", 443, "www.microsoft.com", True, 30.0, "TLSv1.3"), "ok", "прошло"),
    (TlsOutcome("x", 443, "www.microsoft.com", False, error="reset"), "risk", "сброшено после ClientHello"),
    (TlsOutcome("x", 443, "www.microsoft.com", False, error="tls-error"), "ok", "не TLS-сервер"),
])
async def test_tls_probe_results(services, monkeypatch, outcome, verdict, needle):
    script_probes(monkeypatch, {22: "open", 443: "open"})

    async def tls(ip, port, sni, timeout):
        return outcome

    monkeypatch.setattr(verify_mod, "tls_probe", tls)
    report = await verify_ip(services, "46.21.96.10", live=True, sni="www.microsoft.com")
    assert report.tls is not None and report.verdict == verdict
    assert any(needle in f.text for f in report.findings)


async def test_real_tcp_and_tls_probes_against_local_server():
    """Реальные сокеты: открытый порт → open, закрытый → не open; TLS к не-TLS серверу → неудача."""
    import asyncio

    from shadow_scout.net.liveprobe import probe_one, tls_probe

    async def handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert (await probe_one("127.0.0.1", port, 2)).result == "open"
        assert not (await tls_probe("127.0.0.1", port, "example.com", 2)).ok
    finally:
        server.close()
        await server.wait_closed()
    # закрытый порт: Linux/macOS отвечают отказом сразу, Windows повторяет SYN ~2 с — главное, что он не «open»
    assert (await probe_one("127.0.0.1", port, 1)).result in ("refused", "timeout")


# ───────────────────────── CLI ─────────────────────────
def test_cli_verify_blocked_exits_3_and_writes_json(patched_services, tmp_path):
    out = tmp_path / "v.json"
    result = CliRunner().invoke(app, ["verify", "95.217.165.190", "46.21.96.10", "--json", str(out), "--quiet"])
    assert result.exit_code == 3, result.output
    assert "Заблокирован" in result.output and "Адрес чистый" in result.output and "HETZNER-AS" in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [d["verdict"] for d in data] == ["blocked", "ok"]


def test_cli_verify_rejects_private_address(patched_services):
    result = CliRunner().invoke(app, ["verify", "10.1.2.3", "--quiet"])
    assert result.exit_code == 2 and "не глобальный адрес" in result.output


def test_cli_verify_live_with_closed_port(patched_services, monkeypatch):
    script_probes(monkeypatch, {})
    result = CliRunner().invoke(app, ["verify", "46.21.96.10", "--live", "--ports", "22", "--quiet"])
    assert result.exit_code == 0 and "Ни один порт не ответил" in result.output and "Есть риск" in result.output
