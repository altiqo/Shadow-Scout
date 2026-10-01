"""Агрегация сигналов в итоговую оценку: риск 0..100, выживаемость, уверенность, вердикт, рекомендации."""

from __future__ import annotations

from shadow_scout.config import ScoringSettings
from shadow_scout.models import RiskReport, Signal, SignalStatus, Verdict
from shadow_scout.providers import CountryTable


def verdict_for(score: float, thresholds) -> Verdict:
    if score <= thresholds.low_max:
        return "low"
    if score <= thresholds.moderate_max:
        return "moderate"
    if score <= thresholds.high_max:
        return "high"
    return "critical"


def score_report(report: RiskReport, scoring: ScoringSettings, countries: CountryTable) -> RiskReport:
    signals: list[Signal] = report.signals
    available = [s for s in signals if s.status == SignalStatus.OK and s.risk is not None]
    considered = [s for s in signals if s.status != SignalStatus.SKIPPED]
    total_weight = sum(s.weight for s in considered) or 1.0
    avail_weight = sum(s.weight for s in available)
    risk = (sum(s.risk * s.weight for s in available) / avail_weight * 100) if avail_weight else 0.0
    confidence = avail_weight / total_weight

    hard_flags: list[str] = []
    thresholds = scoring.thresholds
    overlap = report.signal("blocklist_overlap")
    if overlap and overlap.status == SignalStatus.OK and overlap.details.get("share", 0) >= thresholds.hard_blocked_share:
        hard_flags.append(f"≥{thresholds.hard_blocked_share:.0%} адресного пространства ASN в списках блокировок")
    cc = report.signal("cheburcheck_asn")
    if cc and cc.status == SignalStatus.OK and cc.details.get("ratio", 0) >= thresholds.hard_blocked_share:
        hard_flags.append("cheburcheck: большинство префиксов ASN заблокировано")
    if report.provider.rkn_hoster_registry:
        hard_flags.append("Провайдер в реестре хостеров РКН")
    site = report.signal("cheburcheck_site")
    if site and site.status == SignalStatus.OK and (site.risk or 0) >= 0.9:
        hard_flags.append("Сайт провайдера в реестре РКН")

    if hard_flags:
        risk = max(risk, 80.0)
    elif report.provider.ru_ties:
        risk = max(risk, 60.0)

    report.risk_score = round(min(100.0, max(0.0, risk)), 1)
    report.survivability = round(100.0 - report.risk_score, 1)
    report.confidence = round(confidence, 2)
    report.hard_flags = hard_flags
    no_network_data = not report.asns or not any(a.prefixes_v4 for a in report.asns)
    if hard_flags:
        report.verdict = verdict_for(report.risk_score, thresholds)
    elif no_network_data or confidence < 0.4:
        report.verdict = "unknown"
    else:
        report.verdict = verdict_for(report.risk_score, thresholds)
    report.recommendations = build_recommendations(report, countries)
    return report


def build_recommendations(report: RiskReport, countries: CountryTable) -> list[str]:
    p = report.provider
    out: list[str] = []
    if report.verdict in ("critical",):
        out.append("Не рекомендуется для VPN: сеть массово присутствует в списках блокировок или провайдер подконтролен РКН.")
    elif report.verdict == "high":
        out.append("Высокий риск: берите только с тестовым периодом и проверяйте доступность из РФ до оплаты.")
    if p.trial:
        out.append("Есть trial — разверните сервер, проверьте доступность из РФ (cheburcheck.ru / ваш мобильный и домашний провайдер) и только затем платите.")
    elif p.hourly:
        out.append("Почасовая оплата — создайте сервер на час, проверьте IP через cheburcheck.ru и живую пробу, пересоздайте при «грязном» IP.")
    else:
        out.append("Нет trial и почасовой оплаты — уточните политику возврата или начните с минимального тарифа на 1 месяц.")
    overlap = report.signal("blocklist_overlap")
    if overlap and overlap.status == SignalStatus.OK and 0 < overlap.details.get("share", 0) < 0.2:
        out.append("Часть подсетей уже в списках: после выдачи IP сразу проверьте его подсеть (cheburcheck.ru) и просите замену при совпадении.")
    nt = report.signal("network_type")
    if nt and nt.risk is not None and nt.risk >= 0.45:
        out.append("Пул датацентровый (DCH): блокируется по подсетям проще, чем ISP-пул. Если есть выбор — предпочитайте ISP/бизнес-диапазоны.")
    best_locs = [loc for loc in report.matched_locations] or p.locations
    low = [loc for loc in best_locs if countries.get(loc.country).radar == "low"]
    if low:
        out.append("Предпочтительные локации: " + ", ".join(sorted({f"{countries.name(loc.country)}{' / ' + loc.city if loc.city else ''}" for loc in low})[:4]) + ".")
    out.append("Чистый IP не защищает от DPI: используйте маскирующиеся протоколы (VLESS+Reality, Shadowsocks-2022, AmneziaWG, Hysteria2) и нестандартные SNI.")
    return out
