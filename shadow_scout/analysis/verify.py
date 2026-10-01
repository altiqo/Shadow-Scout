"""Проверка конкретного IP — то, что нужно сделать сразу после выдачи сервера (trial / почасовая оплата) и до оплаты.

В отличие от оценки провайдера смотрим на сам адрес: он и его подсеть в списках блокировок, что говорит cheburcheck,
как адрес классифицирует ip-api и отвечает ли он с этой машины (TCP и, при желании, TLS с нужным SNI).
"""

from __future__ import annotations

import ipaddress
import time
from typing import Literal

from pydantic import BaseModel, Field

from shadow_scout.analysis.engine import Services
from shadow_scout.net.http import HttpError
from shadow_scout.net.liveprobe import control_reachable, probe_one, tls_probe

Level = Literal["ok", "info", "warn", "bad"]
IpVerdict = Literal["ok", "risk", "blocked", "unknown"]

IP_VERDICT_LABELS = {"ok": "Адрес чистый", "risk": "Есть риск", "blocked": "Заблокирован", "unknown": "Недостаточно данных"}
SUBNET_RISK_SHARE = 0.10  # доля /24 в списках, с которой подсеть считаем рискованной
ASN_RISK_SHARE = 0.25


class Finding(BaseModel):
    level: Level
    text: str


class PortResult(BaseModel):
    port: int
    result: str  # open | refused | timeout | unreachable
    latency_ms: float | None = None


class TlsResult(BaseModel):
    port: int
    sni: str
    ok: bool
    latency_ms: float | None = None
    version: str | None = None
    error: str = ""


class IpReport(BaseModel):
    ip: str
    verdict: IpVerdict = "unknown"
    asn: int | None = None
    holder: str | None = None
    country: str | None = None
    city: str | None = None
    prefix: str | None = None  # анонсируемый префикс, в который входит адрес
    subnet: str | None = None  # /24 (для IPv6 — /64), в котором смотрим «соседей»
    lists_hit: list[str] = Field(default_factory=list)  # списки, в которых есть именно этот адрес
    subnet_blocked_share: float = 0.0
    blocked_neighbours: list[str] = Field(default_factory=list)
    asn_blocked_share: float | None = None
    cheburcheck_blocked: bool | None = None
    cheburcheck_subnets: list[str] = Field(default_factory=list)
    complaints: int | None = None
    hosting: bool | None = None
    proxy: bool | None = None
    ports: list[PortResult] = Field(default_factory=list)
    control_ok: bool | None = None
    tls: TlsResult | None = None
    findings: list[Finding] = Field(default_factory=list)
    recommendation: str = ""
    duration_seconds: float = 0.0


def parse_ip(text: str) -> str:
    """Нормализует и проверяет адрес; частные/служебные адреса проверять бессмысленно."""
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError as exc:
        raise ValueError(f"«{text}» — не IP-адрес") from exc
    if not addr.is_global:
        raise ValueError(f"{addr} — не глобальный адрес (частный, служебный или зарезервированный), проверять нечего")
    return str(addr)


def subnet_of(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


async def verify_ip(
    services: Services,
    ip: str,
    *,
    ports: list[int] | None = None,
    live: bool = False,
    sni: str | None = None,
    timeout: float = 4.0,
) -> IpReport:
    """Полная проверка адреса. live=True добавляет TCP-пробы (и TLS при заданном sni) с этой машины."""
    started = time.monotonic()
    ip = parse_ip(ip)
    report = IpReport(ip=ip, subnet=subnet_of(ip))
    bundle = await services.ensure_blocklists()

    # ── сеть: ASN, префикс, держатель, геолокация ──
    try:
        info = await services.ripe.network_info(ip)
        report.prefix = info.get("prefix")
        if info.get("asns"):
            report.asn = info["asns"][0]
    except HttpError:
        pass
    if report.asn is not None:
        try:
            report.holder = (await services.ripe.as_overview(report.asn)).get("holder")
        except HttpError:
            record = await services.asn_names.get(report.asn)
            report.holder = record.description if record else None
    geo = await services.ripe.geo_for_ip(ip)
    report.country, report.city = geo.get("country"), geo.get("city")

    # ── локальные списки: сам адрес, его подсеть, весь ASN ──
    if bundle.ok_lists:
        report.lists_hit = bundle.is_blocked_ip(ip)
        blocked, total, _hits = bundle.blocked_overlap(report.subnet)
        report.subnet_blocked_share = (blocked / total) if total else 0.0
        if blocked:
            for item in bundle.ok_lists:
                for cidr in item.networks.overlapping_cidrs(report.subnet, limit=5):
                    if cidr not in report.blocked_neighbours:
                        report.blocked_neighbours.append(cidr)
        if report.asn is not None:
            prefixes, _src = await services.prefixes.prefixes(report.asn)
            v4 = [p for p in prefixes if ":" not in p]
            size = blocked_total = 0
            for prefix in v4:
                b, s, _h = bundle.blocked_overlap(prefix)
                blocked_total += b
                size += s
            report.asn_blocked_share = (blocked_total / size) if size else None

    # ── cheburcheck: адрес и жалобы пользователей ──
    cc_error = ""
    if services.cheburcheck.enabled:
        try:
            res = await services.cheburcheck.check(ip)
        except HttpError as exc:
            res, cc_error = None, str(exc)
        if res:
            report.cheburcheck_blocked = bool(res.get("blocked")) and bool(res.get("blocked_subnets") or res.get("rkn_domain"))
            report.cheburcheck_subnets = list(res.get("blocked_subnets") or [])
            report.complaints = res.get("complaints_total")

    # ── ip-api: как классифицируется адрес ──
    try:
        classified = (await services.ipapi.lookup_many([ip])).get(ip)
    except HttpError:
        classified = None
    if classified and classified.get("ok"):
        report.hosting, report.proxy = classified.get("hosting"), classified.get("proxy")

    # ── живые пробы с этой машины ──
    if live:
        ports = ports or [22, 443]
        report.control_ok = await control_reachable(services.settings.live_probe)
        if report.control_ok:
            for port in ports:
                outcome = await probe_one(ip, port, timeout)
                report.ports.append(PortResult(port=port, result=outcome.result, latency_ms=round(outcome.latency_ms, 1) if outcome.latency_ms else None))
            if sni:
                port = 443 if 443 in ports else ports[0]
                t = await tls_probe(ip, port, sni, timeout)
                report.tls = TlsResult(port=port, sni=sni, ok=t.ok, latency_ms=round(t.latency_ms, 1) if t.latency_ms else None, version=t.version, error=t.error)

    _judge(report, bundle_ok=bool(bundle.ok_lists), cc_error=cc_error, live=live)
    report.duration_seconds = round(time.monotonic() - started, 2)
    return report


def _judge(report: IpReport, *, bundle_ok: bool, cc_error: str, live: bool) -> None:
    """Складывает находки и выносит вердикт: blocked → risk → ok; без данных — unknown."""
    f = report.findings
    bad = risky = False

    if not bundle_ok:
        f.append(Finding(level="warn", text="Списки блокировок не загружены — проверка по спискам невозможна (выполните «Обновить списки»)."))
    elif report.lists_hit:
        bad = True
        f.append(Finding(level="bad", text="Адрес есть в списках блокировок: " + ", ".join(report.lists_hit)))
    else:
        f.append(Finding(level="ok", text="Самого адреса нет ни в одном из загруженных списков."))

    if bundle_ok and report.subnet_blocked_share > 0 and not report.lists_hit:
        share = report.subnet_blocked_share
        text = f"{share:.0%} адресов подсети {report.subnet} в списках" + (f" (например, {', '.join(report.blocked_neighbours[:3])})" if report.blocked_neighbours else "")
        if share >= SUBNET_RISK_SHARE:
            risky = True
            f.append(Finding(level="warn", text=text + " — соседей по подсети уже блокируют, дойдёт и до вас."))
        else:
            f.append(Finding(level="info", text=text + "."))
    elif bundle_ok and not report.lists_hit:
        f.append(Finding(level="ok", text=f"Подсеть {report.subnet} в списках не найдена."))

    if report.asn_blocked_share is not None:
        text = f"AS{report.asn} ({report.holder or '?'}): {report.asn_blocked_share:.1%} адресного пространства в списках."
        if report.asn_blocked_share >= ASN_RISK_SHARE:
            risky = True
            f.append(Finding(level="warn", text=text + " Сеть массово блокируется."))
        else:
            f.append(Finding(level="info", text=text))

    if report.cheburcheck_blocked:
        bad = True
        f.append(Finding(level="bad", text="cheburcheck: адрес/подсеть заблокированы" + (f" ({', '.join(report.cheburcheck_subnets[:3])})" if report.cheburcheck_subnets else "") + "."))
    elif report.cheburcheck_blocked is False:
        f.append(Finding(level="ok", text="cheburcheck: адрес не числится заблокированным."))
    elif cc_error:
        f.append(Finding(level="info", text=f"cheburcheck недоступен ({cc_error[:60]}) — проверьте адрес на cheburcheck.ru вручную."))
    if report.complaints:
        risky = True
        f.append(Finding(level="warn", text=f"cheburcheck: {report.complaints} жалоб пользователей на недоступность за 14 дней."))

    if report.hosting is True:
        f.append(Finding(level="info", text="ip-api: датацентровый адрес (hosting) — типично для VPS." + (" Помечен как proxy/VPN." if report.proxy else "")))
        if report.proxy:
            risky = True
    elif report.hosting is False:
        f.append(Finding(level="info", text="ip-api: адрес не помечен как hosting (похож на резидентный/ISP)."))

    if live:
        if report.control_ok is False:
            f.append(Finding(level="warn", text="Контрольный хост недоступен — нет интернета или всё фильтруется; пробы пропущены."))
        elif report.ports:
            alive = [p for p in report.ports if p.result in ("open", "refused")]
            ports_text = ", ".join(f"{p.port}:{p.result}" + (f" {p.latency_ms:.0f} мс" if p.latency_ms else "") for p in report.ports)
            if alive:
                f.append(Finding(level="ok", text=f"Адрес достижим с этой машины ({ports_text})."))
            else:
                risky = True
                f.append(Finding(level="warn", text=f"Ни один порт не ответил ({ports_text}): либо он закрыт файрволом сервера, либо адрес фильтруется. "
                                                    "Повторите с мобильного интернета / другого провайдера — если там отвечает, адрес режется."))
        if report.tls is not None:
            t = report.tls
            if t.ok:
                f.append(Finding(level="ok", text=f"TLS-рукопожатие с SNI {t.sni} на порту {t.port} прошло ({t.version or 'TLS'}, {t.latency_ms or 0:.0f} мс) — трафик с таким SNI проходит."))
            else:
                reason = {"reset": "соединение сброшено после ClientHello (характерно для DPI/ТСПУ)", "timeout": "таймаут", "tls-error": "порт отвечает, но это не TLS-сервер", "refused": "порт закрыт"}.get(t.error, t.error)
                risky = risky or t.error in ("reset", "timeout")
                f.append(Finding(level="warn", text=f"TLS-рукопожатие с SNI {t.sni} на порту {t.port} не удалось: {reason}."))

    known = bundle_ok or report.cheburcheck_blocked is not None
    if bad:
        report.verdict = "blocked"
        report.recommendation = "Адрес уже в блок-листах — не платите: пересоздайте сервер (получите другой IP) или попробуйте другую локацию/провайдера."
    elif risky:
        report.verdict = "risk"
        report.recommendation = "Адрес пока не заблокирован, но риск повышен: если есть почасовая оплата — пересоздайте сервер ради более чистой подсети; иначе берите минимальный срок."
    elif known:
        report.verdict = "ok"
        report.recommendation = "По открытым данным адрес чистый. Перед оплатой убедитесь в достижимости с вашей сети (живые пробы) и используйте маскирующиеся протоколы (VLESS+Reality, Shadowsocks-2022, AmneziaWG, Hysteria2)."
    else:
        report.verdict = "unknown"
        report.recommendation = "Источников для проверки недостаточно — загрузите списки блокировок и повторите, либо проверьте адрес на cheburcheck.ru вручную."
