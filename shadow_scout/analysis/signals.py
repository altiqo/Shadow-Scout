"""Сигналы риска: каждая функция превращает собранные данные в Signal с нормализованным риском 0..1."""

from __future__ import annotations

import math
from typing import Any

from shadow_scout.config import ScoringWeights
from shadow_scout.models import AsnInfo, Provider, Signal, SignalStatus
from shadow_scout.net.peeringdb import PeeringDbClient
from shadow_scout.providers import CountryTable


def _fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def _plural(n: int, one: str, few: str, many: str) -> str:
    n_abs = abs(n) % 100
    last = n_abs % 10
    if 10 < n_abs < 20:
        return many
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def _share_curve(share: float, full_at: float = 0.2, floor: float = 0.1, power: float = 0.6) -> float:
    if share <= 0:
        return 0.0
    return min(1.0, floor + (1 - floor) * (min(share, full_at) / full_at) ** power)


def unavailable(key: str, title: str, weight: float, reason: str) -> Signal:
    return Signal(key=key, title=title, weight=weight, risk=None, status=SignalStatus.UNAVAILABLE, summary=reason)


def skipped(key: str, title: str, weight: float, reason: str) -> Signal:
    return Signal(key=key, title=title, weight=weight, risk=None, status=SignalStatus.SKIPPED, summary=reason)


# ───────────────────────── 1. Локальные списки блокировок ─────────────────────────
def blocklist_overlap(asns: list[AsnInfo], weights: ScoringWeights, lists_ok: bool) -> Signal:
    key, title, w = "blocklist_overlap", "Пересечение с базами блокировок", weights.blocklist_overlap
    if not lists_ok:
        return unavailable(key, title, w, "списки блокировок не загружены")
    with_prefixes = [a for a in asns if a.prefixes_v4]
    if not with_prefixes:
        return unavailable(key, title, w, "нет данных о префиксах ASN")
    total = sum(a.ipv4_count for a in with_prefixes)
    blocked = sum(a.blocked_ipv4_count for a in with_prefixes)
    share = blocked / total if total else 0.0
    blocked_prefixes = sum(len(a.blocked_prefixes) for a in with_prefixes)
    total_prefixes = sum(len(a.prefixes_v4) for a in with_prefixes)
    prefix_share = blocked_prefixes / total_prefixes if total_prefixes else 0.0
    risk = max(_share_curve(share), 0.75 * _share_curve(prefix_share, full_at=0.5))
    if blocked == 0:
        summary = f"Ни один из {_fmt_int(total)} IPv4-адресов не найден в списках"
    else:
        summary = (
            f"Заблокировано {share:.2%} адресного пространства "
            f"({_fmt_int(blocked)} из {_fmt_int(total)} IPv4), затронуто {blocked_prefixes} из {total_prefixes} префиксов"
        )
    return Signal(
        key=key, title=title, weight=w, risk=risk, summary=summary,
        details={
            "blocked_ipv4": blocked, "total_ipv4": total, "share": share,
            "blocked_prefixes": blocked_prefixes, "total_prefixes": total_prefixes,
            "examples": [p for a in with_prefixes for p in a.blocked_prefixes[:5]][:10],
        },
    )


# ───────────────────────── 2. cheburcheck: проверка ASN ─────────────────────────
def cheburcheck_asn(results: list[dict[str, Any]], weights: ScoringWeights, enabled: bool, error: str | None) -> Signal:
    key, title, w = "cheburcheck_asn", "cheburcheck.ru: ASN в реестре", weights.cheburcheck_asn
    if not enabled:
        return skipped(key, title, w, "cheburcheck отключён в настройках")
    if error and not results:
        return unavailable(key, title, w, f"cheburcheck недоступен: {error}")
    if not results:
        return unavailable(key, title, w, "нет ответа по ASN")
    total_prefixes = 0
    blocked_prefixes = 0
    blocked_flag = False
    examples: list[str] = []
    for res in results:
        info = res.get("asn_info") or {}
        prefixes = info.get("prefixes") or []
        blocked = info.get("blocked_prefixes") or []
        total_prefixes += len(prefixes)
        blocked_prefixes += len(blocked)
        blocked_flag = blocked_flag or bool(res.get("blocked"))
        examples.extend(blocked[:5])
    ratio = blocked_prefixes / total_prefixes if total_prefixes else 0.0
    if total_prefixes == 0:
        risk = 0.6 if blocked_flag else None
        if risk is None:
            return unavailable(key, title, w, "cheburcheck не вернул префиксы ASN")
        summary = "cheburcheck пометил цель как заблокированную (без деталей по префиксам)"
    else:
        risk = _share_curve(ratio, full_at=0.5, floor=0.15, power=0.7) if blocked_prefixes else 0.0
        if blocked_prefixes == 0:
            summary = f"cheburcheck: 0 из {total_prefixes} префиксов в списках блокировок"
        else:
            summary = f"cheburcheck: {blocked_prefixes} из {total_prefixes} префиксов ({ratio:.1%}) в списках блокировок"
    return Signal(
        key=key, title=title, weight=w, risk=risk, summary=summary,
        details={"blocked_prefixes": blocked_prefixes, "total_prefixes": total_prefixes, "ratio": ratio, "examples": examples[:10]},
    )


# ───────────────────────── 3. cheburcheck: сайт провайдера ─────────────────────────
def cheburcheck_site(result: dict[str, Any] | None, domain: str | None, weights: ScoringWeights, enabled: bool, error: str | None) -> Signal:
    key, title, w = "cheburcheck_site", "cheburcheck.ru: сайт провайдера", weights.cheburcheck_site
    if not enabled:
        return skipped(key, title, w, "cheburcheck отключён в настройках")
    if not domain:
        return skipped(key, title, w, "у провайдера не указан сайт")
    if result is None:
        return unavailable(key, title, w, f"нет данных по {domain}" + (f": {error}" if error else ""))
    if result.get("rkn_domain"):
        risk, summary = 0.9, f"Домен {domain} находится в реестре РКН ({result['rkn_domain']})"
    elif result.get("blocked_subnets"):
        risk, summary = 0.6, f"Подсеть сайта {domain} в списках: {', '.join(result['blocked_subnets'][:3])}"
    elif result.get("blocked") and result.get("cdn_providers"):
        risk, summary = 0.25, f"Сайт {domain} за CDN ({', '.join(result['cdn_providers'][:2])}) — косвенный признак"
    elif result.get("blocked"):
        risk, summary = 0.5, f"cheburcheck пометил {domain} как заблокированный"
    else:
        risk, summary = 0.0, f"Сайт {domain} не числится в реестре РКН"
    return Signal(
        key=key, title=title, weight=w, risk=risk, summary=summary,
        details={"domain": domain, "ips": result.get("ips", [])[:4], "geo": result.get("geo"), "cdn": result.get("cdn_providers")},
    )


# ───────────────────────── 4. Размер сети ─────────────────────────
def asn_size(asns: list[AsnInfo], weights: ScoringWeights, small_threshold: int) -> Signal:
    key, title, w = "asn_size", "Размер сети (IPv4)", weights.asn_size
    total = sum(a.ipv4_count for a in asns)
    if total == 0:
        return unavailable(key, title, w, "размер сети неизвестен")
    steps = [(2048, 0.0), (8192, 0.1), (32768, 0.25), (131072, 0.45), (524288, 0.65), (2_097_152, 0.85)]
    risk = 1.0
    for limit, value in steps:
        if total <= limit:
            risk = value
            break
    bits = 32 - int(math.log2(total)) if total > 0 else 32
    label = "маленькая" if total <= small_threshold else ("средняя" if total <= 131072 else "крупная")
    summary = f"{label.capitalize()} сеть: {_fmt_int(total)} IPv4 (~/{bits}), {sum(len(a.prefixes_v4) for a in asns)} префиксов"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"ipv4": total, "approx_prefix": bits})


# ───────────────────────── 5. Тип сети (ISP vs DCH) ─────────────────────────
def network_type(provider: Provider, asns: list[AsnInfo], ipapi: dict[str, dict[str, Any]], weights: ScoringWeights) -> Signal:
    key, title, w = "network_type", "Тип IP-пула (ISP / датацентр)", weights.network_type
    evidence: list[tuple[float, float, str]] = []  # (risk, weight, note)
    pdb_classes = [PeeringDbClient.classify(a.peeringdb) for a in asns if a.peeringdb]
    if pdb_classes:
        mapping = {"isp": 0.1, "enterprise": 0.25, "other": 0.4, "content": 0.6, "unknown": 0.45}
        best = min(mapping[c] for c in pdb_classes)
        types = sorted({t for a in asns if a.peeringdb for t in (a.peeringdb.get("info_types") or [])})
        evidence.append((best, 0.4, "PeeringDB: " + (", ".join(types) if types else "тип не указан")))
    if ipapi:
        ok = [v for v in ipapi.values() if v.get("ok")]
        if ok:
            hosting_share = sum(1 for v in ok if v.get("hosting")) / len(ok)
            evidence.append((0.15 + 0.6 * hosting_share, 0.4, f"ip-api: {hosting_share:.0%} выборки помечено как hosting ({len(ok)} IP)"))
    db_map = {"isp": 0.1, "mixed": 0.35, "dch": 0.6, "unknown": 0.45}
    evidence.append((db_map.get(provider.ip_type, 0.45), 0.2, f"база: {provider.ip_type.upper()}"))
    total_w = sum(e[1] for e in evidence)
    risk = sum(e[0] * e[1] for e in evidence) / total_w
    verdict = "ISP/резидентный" if risk < 0.25 else ("смешанный" if risk < 0.45 else "датацентр (DCH)")
    summary = f"{verdict}; " + "; ".join(e[2] for e in evidence)
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"evidence": [e[2] for e in evidence]})


# ───────────────────────── 6. Популярность ─────────────────────────
def popularity(provider: Provider, weights: ScoringWeights) -> Signal:
    key, title, w = "popularity", "Популярность у RU-аудитории / масштаб", weights.popularity
    risk = (max(1, min(5, provider.popularity_ru)) - 1) / 4
    size_floor = {"micro": 0.0, "small": 0.0, "medium": 0.2, "large": 0.5, "hyperscale": 0.8}.get(provider.size, 0.0)
    risk = max(risk, size_floor)
    labels = {1: "почти неизвестен", 2: "малоизвестен", 3: "известен", 4: "популярен", 5: "массово используется"}
    summary = f"{labels.get(provider.popularity_ru, '—')} в RU-сообществе; масштаб компании: {provider.size}"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"popularity": provider.popularity_ru, "size": provider.size})


# ───────────────────────── 7. Юрисдикция ─────────────────────────
def jurisdiction(provider: Provider, matched_countries: list[str], countries: CountryTable, weights: ScoringWeights) -> Signal:
    key, title, w = "jurisdiction", "Юрисдикция и локации", weights.jurisdiction
    hq_risk = countries.risk(provider.hq_country)
    location_codes = matched_countries or provider.countries
    loc_risks = [countries.risk(c) for c in location_codes] or [hq_risk]
    loc_risk = min(loc_risks)
    risk = 0.5 * hq_risk + 0.5 * loc_risk
    hq = countries.get(provider.hq_country)
    best_cc = location_codes[loc_risks.index(loc_risk)] if location_codes else provider.hq_country
    summary = f"HQ: {hq.name_ru} ({hq.radar}); лучшая локация: {countries.name(best_cc)} ({countries.get(best_cc).radar})"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"hq": provider.hq_country, "locations": location_codes})


# ───────────────────────── 8. CDN ─────────────────────────
def cdn_membership(asns: list[AsnInfo], weights: ScoringWeights, lists_ok: bool) -> Signal:
    key, title, w = "cdn_membership", "Принадлежность к CDN-диапазонам", weights.cdn_membership
    if not lists_ok:
        return unavailable(key, title, w, "список CDN не загружен")
    total = sum(len(a.prefixes_v4) for a in asns)
    if total == 0:
        return unavailable(key, title, w, "нет префиксов для проверки")
    cdn = sum(len(a.cdn_prefixes) for a in asns)
    fraction = cdn / total
    risk = min(1.0, 2 * fraction)
    summary = "Префиксы не входят в известные CDN-диапазоны" if cdn == 0 else f"{cdn} из {total} префиксов входят в CDN-диапазоны (CDN массово блокируются)"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"cdn_prefixes": cdn, "total": total})


# ───────────────────────── 9. Связи с РФ ─────────────────────────
def ru_ties(provider: Provider, weights: ScoringWeights) -> Signal:
    key, title, w = "ru_ties", "Связи с РФ / реестр хостеров РКН", weights.ru_ties
    if provider.rkn_hoster_registry:
        return Signal(key=key, title=title, weight=w, risk=1.0, summary="Провайдер в реестре хостинг-провайдеров РКН — обязан исполнять требования регулятора")
    if provider.ru_ties:
        return Signal(key=key, title=title, weight=w, risk=0.8, summary="Российские владельцы/юрлицо/аудитория — повышенное внимание РКН и риск давления")
    return Signal(key=key, title=title, weight=w, risk=0.0, summary="Связей с РФ не отмечено")


# ───────────────────────── 10. Жалобы пользователей cheburcheck ─────────────────────────
def complaints(results: list[dict[str, Any]], weights: ScoringWeights, enabled: bool) -> Signal:
    key, title, w = "complaints", "Жалобы пользователей (14 дней)", weights.complaints
    if not enabled:
        return skipped(key, title, w, "cheburcheck отключён")
    if not results:
        return unavailable(key, title, w, "нет данных cheburcheck")
    total = sum(int(r.get("complaints_total") or 0) for r in results)
    if total == 0:
        risk, summary = 0.0, "Жалоб на недоступность за 14 дней нет"
    elif total <= 2:
        risk, summary = 0.3, f"{total} {_plural(total, 'жалоба', 'жалобы', 'жалоб')} на недоступность за 14 дней"
    elif total <= 9:
        risk, summary = 0.6, f"{total} {_plural(total, 'жалоба', 'жалобы', 'жалоб')} на недоступность за 14 дней"
    else:
        risk, summary = 1.0, f"{total} {_plural(total, 'жалоба', 'жалобы', 'жалоб')} за 14 дней — массовые проблемы доступа"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"complaints": total})


# ───────────────────────── 11. Живая проба ─────────────────────────
def live_probe(outcomes: list[dict[str, Any]] | None, control_ok: bool | None, website_ips: list[str], weights: ScoringWeights, enabled: bool) -> Signal:
    key, title, w = "live_probe", "Живая TCP-проба с этой машины", weights.live_probe
    if not enabled:
        return skipped(key, title, w, "живые пробы отключены")
    if control_ok is False:
        return unavailable(key, title, w, "контрольный хост недоступен — нет интернета или всё фильтруется")
    if not outcomes:
        return unavailable(key, title, w, "нет адресов для пробы")
    alive = [o for o in outcomes if o["result"] in ("open", "refused")]
    timeouts = [o for o in outcomes if o["result"] == "timeout"]
    site_outcomes = [o for o in outcomes if o["ip"] in website_ips]
    site_alive = any(o["result"] in ("open", "refused") for o in site_outcomes)
    if site_outcomes and not site_alive:
        risk = 0.9
        summary = f"Сайт провайдера недоступен с этой машины ({len(site_outcomes)} проб), остальные: {len(alive)} ответили"
    elif alive:
        ratio = len(alive) / len(outcomes)
        risk = 0.05 if ratio >= 0.3 else 0.25
        summary = f"Ответили {len(alive)} из {len(outcomes)} проб ({len(timeouts)} таймаутов — обычно пустые адреса)"
    else:
        return unavailable(key, title, w, f"ни один из {len(outcomes)} адресов не ответил — невозможно отличить фильтрацию от пустых адресов")
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"alive": len(alive), "total": len(outcomes), "site_alive": site_alive if site_outcomes else None})


# ───────────────────────── 12. Фрагментация ─────────────────────────
def asn_fragmentation(asns: list[AsnInfo], weights: ScoringWeights) -> Signal:
    key, title, w = "asn_fragmentation", "Фрагментация адресного пространства", weights.asn_fragmentation
    prefixes = [p for a in asns for p in a.prefixes_v4]
    if not prefixes:
        return unavailable(key, title, w, "нет префиксов")
    small = sum(1 for p in prefixes if int(p.split("/")[-1]) >= 24)
    share = small / len(prefixes)
    if len(prefixes) >= 20 and share >= 0.7:
        risk, summary = 0.5, f"{small} из {len(prefixes)} префиксов — /24 и мельче: похоже на арендованные пулы (часто «грязные»)"
    elif len(prefixes) >= 50:
        risk, summary = 0.3, f"{len(prefixes)} префиксов — крупная, разнородная сеть"
    else:
        risk, summary = 0.1, f"{len(prefixes)} префиксов, {share:.0%} из них /24 и мельче"
    return Signal(key=key, title=title, weight=w, risk=risk, summary=summary, details={"prefixes": len(prefixes), "small_share": share})
