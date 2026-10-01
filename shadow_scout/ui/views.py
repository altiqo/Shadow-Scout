"""Рендеринг результатов в терминале: таблицы, карточки отчётов, статусы источников."""

from __future__ import annotations

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shadow_scout.analysis.discovery import Candidate
from shadow_scout.config import Settings
from shadow_scout.export.common import fmt_int, holder_label, yes_no
from shadow_scout.models import VERDICT_LABELS_RU, RiskReport, SearchResult, SignalStatus, SourceStatus
from shadow_scout.providers import ProviderDB, load_countries
from shadow_scout.selection import Plan
from shadow_scout.ui.theme import score_bar, verdict_style


def flag_cell(value: bool | None, hint: bool = False) -> Text:
    """✓ подтверждено · ~ определено автоматически · ? неизвестно · — нет."""
    if value is None:
        return Text("?", style="muted")
    if not value:
        return Text("—", style="muted")
    return Text("~", style="warn") if hint else Text("✓", style="ok")


def depth_cell(report: RiskReport) -> Text:
    return Text("●", style="ok") if report.depth == "full" else Text("◐", style="warn")


def location_label(country: str, city: str | None = None) -> str:
    name = load_countries().name(country)
    return f"{name} ({country})" + (f" · {city}" if city else "")


def plan_line(plan: Plan) -> Text:
    text = Text()
    text.append("Кандидатов в базе: ", style="muted")
    text.append(f"{plan.matched}", style="bold")
    text.append(f" · анализируем {len(plan.candidates)} — лучших на каждую локацию", style="muted")
    if plan.dropped:
        text.append(f" (ещё {plan.dropped} не вошли в потолок)", style="muted")
    thin = plan.thin_locations
    if thin:
        names = ", ".join(f"{location_label(cc, city)}: {plan.groups[(cc, city)]}" for cc, city in thin[:6])
        text.append(f"\nМало вариантов в базе — {names}" + (" …" if len(thin) > 6 else ""), style="warn")
        text.append("  → «shadow-scout harvest» или discovery добавят больше", style="muted")
    return text


def picks_view(result: SearchResult) -> Table | Panel:
    """Лучшие провайдеры по каждой локации (страна или город): главный экран результата поиска."""
    if not result.picks:
        return Panel(Text("Рекомендовать некого: все проанализированные провайдеры критичны или по ним нет данных.", style="warn"), border_style="yellow")
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", expand=True, pad_edge=False)
    table.add_column("Локация / провайдер", min_width=26, overflow="fold")
    table.add_column("Город", min_width=10, overflow="fold")
    table.add_column("ASN", min_width=8, overflow="fold")
    table.add_column("IPv4", justify="right", min_width=7)
    table.add_column("Блок.", justify="right", width=6)
    table.add_column("Trial", width=5, justify="center")
    table.add_column("Почас.", width=6, justify="center")
    table.add_column("от €", justify="right", width=5)
    table.add_column("Выживаемость", min_width=15)
    table.add_column("Вердикт", min_width=12)
    table.add_column("Пров.", width=5, justify="center")
    for pick in result.picks:
        header = Text(location_label(pick.country, pick.city), style="bold #7c9cff")
        header.append(f"   в базе подошло {pick.candidates}, проанализировано {pick.analyzed}", style="muted")
        table.add_section()
        table.add_row(header)
        if not pick.provider_ids:
            reason = "в базе нет подходящих провайдеров" if not pick.candidates else "рекомендовать некого: все проанализированные критичны или без данных"
            table.add_row(Text(f"  {reason}", style="warn"))
        for rank, pid in enumerate(pick.provider_ids, start=1):
            r = result.report_by_id(pid)
            if r is None:
                continue
            p = r.provider
            name = Text(f" {rank}. {p.name}", style="bold")
            if p.source == "catalog":
                name.append(" [авто]", style="muted")
            cities = ", ".join(sorted({loc.city for loc in p.locations if loc.country == pick.country and loc.city}))[:40]
            blocked = f"{r.blocked_share * 100:.1f}%" if r.total_ipv4 else "—"
            blocked_style = "ok" if r.blocked_share == 0 else ("warn" if r.blocked_share < 0.05 else "bad")
            table.add_row(
                name, cities or "—", ", ".join(f"AS{a.asn}" for a in r.asns) or "—", fmt_int(r.total_ipv4) if r.total_ipv4 else "—",
                Text(blocked, style=blocked_style if r.total_ipv4 else "muted"),
                flag_cell(p.trial, p.hints_only), flag_cell(p.hourly, p.hints_only),
                f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—",
                score_bar(r.survivability, 10, r.verdict), verdict_text(r.verdict), depth_cell(r),
            )
    return table


def ip_report_panel(report) -> Panel:
    """Карточка проверки IP: вердикт, где находится адрес, находки и что делать."""
    from shadow_scout.analysis.verify import IP_VERDICT_LABELS

    style = {"ok": "verdict.low", "risk": "verdict.moderate", "blocked": "verdict.critical", "unknown": "verdict.unknown"}[report.verdict]
    head = Table.grid(padding=(0, 2))
    head.add_column(style="muted")
    head.add_column()
    head.add_row("Адрес", report.ip)
    head.add_row("Сеть", f"AS{report.asn} · {report.holder or '?'}" if report.asn else "ASN не определён")
    head.add_row("Префикс / подсеть", f"{report.prefix or '—'} / {report.subnet}")
    place = ", ".join(x for x in (load_countries().name(report.country) if report.country else None, report.city) if x)
    head.add_row("Геолокация", place or "—")
    icons = {"ok": ("✔", "ok"), "info": ("•", "muted"), "warn": ("⚠", "warn"), "bad": ("✖", "bad")}
    lines = Text()
    for finding in report.findings:
        icon, icon_style = icons[finding.level]
        lines.append(f" {icon} ", style=icon_style)
        lines.append(finding.text + "\n")
    verdict = Text(IP_VERDICT_LABELS[report.verdict], style=style)
    verdict.append(f"   проверено за {report.duration_seconds:.1f} с", style="muted")
    body = Group(verdict, Text(""), head, Text("\nНаходки", style="bold"), lines, Text("Что делать", style="bold"), Text("→ " + report.recommendation))
    return Panel(body, title=f"[bold]{report.ip}[/bold]", border_style=style, padding=(1, 2))


def dbcheck_table(issues) -> Table:
    """Проблемы базы: ошибки сверху, затем предупреждения и замечания."""
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", pad_edge=False, expand=True)
    table.add_column("", width=2)
    table.add_column("Провайдер", min_width=18, overflow="fold")
    table.add_column("Код", min_width=16)
    table.add_column("Что не так", overflow="fold")
    marks = {"error": ("✖", "bad"), "warn": ("⚠", "warn"), "info": ("•", "muted")}
    for issue in issues:
        mark, style = marks[issue.level]
        table.add_row(Text(mark, style=style), Text(issue.name, style="bold"), issue.code, issue.message)
    return table


def country_stats_table(db: ProviderDB) -> Table:
    """Сколько провайдеров в базе приходится на каждую страну — видно «бедные» локации."""
    countries = load_countries()
    stats = db.country_stats()
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", pad_edge=False)
    table.add_column("Страна", min_width=24)
    table.add_column("Радар", width=9)
    table.add_column("Всего", justify="right", width=6)
    table.add_column("Ручная база", justify="right", width=11)
    table.add_column("Каталог", justify="right", width=8)
    table.add_column("Местных", justify="right", width=8)
    for cc, row in sorted(stats.items(), key=lambda kv: (-kv[1]["all"], kv[0])):
        c = countries.get(cc)
        style = "bad" if row["all"] < 3 else ("warn" if row["all"] < 8 else "ok")
        table.add_row(c.label(), c.radar, Text(str(row["all"]), style=style), str(row["curated"]), str(row["catalog"]), str(row["local"]))
    return table


def verdict_text(verdict: str) -> Text:
    return Text(VERDICT_LABELS_RU.get(verdict, verdict), style=verdict_style(verdict))


def results_table(result: SearchResult, limit: int | None = None) -> Table:
    countries = load_countries()
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", expand=True, show_lines=False, pad_edge=False)
    table.add_column("#", justify="right", width=3, style="muted")
    table.add_column("Провайдер", min_width=16, overflow="fold")
    table.add_column("Страны", overflow="fold", min_width=10)
    table.add_column("ASN", min_width=8, overflow="fold")
    table.add_column("IPv4", justify="right", min_width=8)
    table.add_column("Блок.", justify="right", width=6)
    table.add_column("Тип", width=5)
    table.add_column("Trial", width=5, justify="center")
    table.add_column("Почас.", width=6, justify="center")
    table.add_column("от €", justify="right", width=5)
    table.add_column("Выживаемость", min_width=15)
    table.add_column("Вердикт", min_width=12)
    table.add_column("Увер.", justify="right", width=5)
    table.add_column("Пров.", width=5, justify="center")
    reports = result.sorted_reports()
    if limit:
        reports = reports[:limit]
    for rank, r in enumerate(reports, start=1):
        p = r.provider
        locs = r.matched_locations or p.locations
        cc = ", ".join(sorted({countries.name(loc.country) for loc in locs})) or "—"
        asns = ", ".join(f"AS{a.asn}" for a in r.asns) or "—"
        blocked = f"{r.blocked_share*100:.1f}%" if r.total_ipv4 else "—"
        blocked_style = "ok" if r.blocked_share == 0 else ("warn" if r.blocked_share < 0.05 else "bad")
        name = Text(p.name, style="bold")
        if p.source != "bundled":
            name.append(f" [{'авто' if p.source == 'catalog' else p.source}]", style="muted")
        table.add_row(
            str(rank), name, cc, asns, fmt_int(r.total_ipv4) if r.total_ipv4 else "—",
            Text(blocked, style=blocked_style if r.total_ipv4 else "muted"), p.ip_type.upper(),
            flag_cell(p.trial, p.hints_only), flag_cell(p.hourly, p.hints_only),
            f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—",
            score_bar(r.survivability, 10, r.verdict), verdict_text(r.verdict), f"{r.confidence*100:.0f}%", depth_cell(r),
        )
    return table


def summary_line(result: SearchResult) -> Text:
    counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0, "unknown": 0}
    for r in result.reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    text = Text()
    deep = sum(1 for r in result.reports if r.depth == "full")
    text.append(f"{len(result.reports)} провайдеров за {result.duration_seconds:.0f} с (полная проверка: {deep}): ", style="muted")
    for key in ("low", "moderate", "high", "critical", "unknown"):
        text.append(f"{counts[key]} {VERDICT_LABELS_RU[key].lower()}", style=verdict_style(key))
        text.append("  ")
    return text


def report_panel(report: RiskReport) -> Panel:
    countries = load_countries()
    p = report.provider
    locs = report.matched_locations or p.locations
    loc_text = ", ".join(sorted({countries.name(loc.country) + (f" / {loc.city}" if loc.city else "") for loc in locs})) or "—"

    head = Table.grid(padding=(0, 2))
    head.add_column(style="muted")
    head.add_column()
    head.add_row("Сайт", p.website or "—")
    head.add_row("Локации", loc_text)
    head.add_row("Тип IP (база)", f"{p.ip_type.upper()}  · размер: {p.size} · популярность в RU: {p.popularity_ru}/5")
    trial = yes_no(p.trial, p.hints_only) + (f" — {p.trial_note}" if p.trial_note else "")
    head.add_row("Trial / почасовая", f"{trial} / {yes_no(p.hourly, p.hints_only)}")
    if p.vps is not None or p.source == "catalog":
        head.add_row("VPS", {True: "подтверждён на сайте", None: "не подтверждён — проверьте на сайте", False: "не продаёт"}[p.vps])
    head.add_row("Цена / оплата", f"{(f'{p.min_price_eur:g} €/мес' if p.min_price_eur is not None else '—')} · {', '.join(p.payment) or '—'}")
    if p.notes:
        head.add_row("Примечание", p.notes)

    asn_table = Table(box=box.SIMPLE, header_style="muted", pad_edge=False, expand=True)
    asn_table.add_column("ASN", width=9)
    asn_table.add_column("Holder", overflow="fold")
    asn_table.add_column("IPv4", justify="right")
    asn_table.add_column("Префиксов", justify="right")
    asn_table.add_column("В списках", justify="right")
    asn_table.add_column("PeeringDB", overflow="fold")
    for a in report.asns:
        holder = Text(holder_label(report, a.holder), style="muted" if (not a.holder and report.depth == "quick") else "")
        if a.holder_matches_provider is False:
            holder.append("  ⚠ не совпадает", style="warn")
        pdb = "—"
        if a.peeringdb:
            pdb = ", ".join(a.peeringdb.get("info_types") or []) or "тип ?"
            if a.peeringdb.get("info_traffic"):
                pdb += f" · {a.peeringdb['info_traffic']}"
            if a.peeringdb.get("info_scope"):
                pdb += f" · {a.peeringdb['info_scope']}"
        share_style = "ok" if a.blocked_share == 0 else ("warn" if a.blocked_share < 0.05 else "bad")
        asn_table.add_row(f"AS{a.asn}", holder, fmt_int(a.ipv4_count), str(len(a.prefixes_v4)), Text(f"{a.blocked_share:.2%}", style=share_style), pdb)
        if a.blocked_prefixes:
            asn_table.add_row("", Text("заблок.: " + ", ".join(a.blocked_prefixes[:6]) + (" …" if len(a.blocked_prefixes) > 6 else ""), style="muted"), "", "", "", "")
    if not report.asns:
        asn_table.add_row("—", Text("ASN не определён", style="warn"), "", "", "", "")

    sig_table = Table(box=box.SIMPLE, header_style="muted", pad_edge=False, expand=True)
    sig_table.add_column("Сигнал", min_width=24)
    sig_table.add_column("Риск", width=14)
    sig_table.add_column("Вес", width=4, justify="right")
    sig_table.add_column("Описание", overflow="fold")
    for s in report.signals:
        if s.status == SignalStatus.OK and s.risk is not None:
            risk_cell = score_bar(s.risk * 100, 8, s.severity)
            title = Text(s.title)
            summary = Text(s.summary)
        else:
            risk_cell = Text("—  нет данных" if s.status == SignalStatus.UNAVAILABLE else "—  пропущен", style="muted")
            title = Text(s.title, style="muted")
            summary = Text(s.summary, style="muted")
        sig_table.add_row(title, risk_cell, f"{s.weight:g}", summary)

    extras: list[RenderableType] = []
    if report.hard_flags:
        extras.append(Text("⛔ " + " · ".join(report.hard_flags), style="bad"))
    if report.warnings:
        extras.append(Text("\n".join("⚠ " + w for w in report.warnings), style="warn"))
    recs = Text()
    for rec in report.recommendations:
        recs.append("→ ", style="accent")
        recs.append(rec + "\n")

    verdict = Text()
    verdict.append(f"{VERDICT_LABELS_RU.get(report.verdict, report.verdict)}", style=verdict_style(report.verdict))
    verdict.append(f"   выживаемость {report.survivability:.0f}/100 · риск {report.risk_score:.0f} · уверенность {report.confidence*100:.0f}% · {report.duration_seconds:.1f} с", style="muted")

    body = Group(verdict, Text(""), head, Text("\nСети", style="bold"), asn_table, Text("Сигналы риска (0 — безопасно, 100 — максимум)", style="bold"), sig_table, *extras, Text("\nРекомендации", style="bold"), recs)
    return Panel(body, title=f"[bold]{p.name}[/bold]", border_style=verdict_style(report.verdict), padding=(1, 2))


def sources_panel(sources: list[SourceStatus]) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_column(width=2)
    table.add_column(style="bold", min_width=22)
    table.add_column(style="muted", overflow="fold")
    for s in sources:
        table.add_row(Text("●", style="ok") if s.ok else Text("○", style="bad"), s.name, s.detail)
    return Panel(table, title="Источники данных", border_style="#243152", padding=(0, 1))


def discovery_table(candidates: list[Candidate], limit: int = 60) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", expand=True, pad_edge=False)
    table.add_column("#", justify="right", width=3, style="muted")
    table.add_column("ASN", width=9)
    table.add_column("Название", overflow="fold", min_width=20)
    table.add_column("IPv4", justify="right")
    table.add_column("Преф.", justify="right", width=5)
    table.add_column("В списках", justify="right", width=9)
    table.add_column("PeeringDB", min_width=10)
    table.add_column("Трафик", min_width=8)
    table.add_column("Сайт", overflow="fold")
    for i, c in enumerate(candidates[:limit], start=1):
        share_style = "ok" if c.blocked_share == 0 else ("warn" if c.blocked_share < 0.05 else "bad")
        table.add_row(
            str(i), f"AS{c.asn}", c.name or "?", fmt_int(c.ipv4_count), str(c.prefixes),
            Text(f"{c.blocked_share:.2%}", style=share_style), c.pdb_type, c.pdb_traffic or "—", c.website or "—",
        )
    return table


def providers_table(db: ProviderDB, providers) -> Table:
    countries = load_countries()
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold #7c9cff", expand=True, pad_edge=False)
    table.add_column("id", style="muted", min_width=10)
    table.add_column("Провайдер", min_width=16)
    table.add_column("HQ", width=4)
    table.add_column("Локации", overflow="fold")
    table.add_column("ASN", overflow="fold")
    table.add_column("Разм.", width=6)
    table.add_column("Поп.", width=4, justify="center")
    table.add_column("Тип", width=5)
    table.add_column("Trial", width=5, justify="center")
    table.add_column("Почас.", width=6, justify="center")
    table.add_column("от €", width=5, justify="right")
    table.add_column("Статус", width=8)
    table.add_column("Источник", width=9)
    for p in providers:
        disabled = p.id in db.disabled_ids or not p.enabled
        status = Text("откл.", style="muted") if disabled else (Text("RU", style="bad") if p.ru_ties else Text("ok", style="ok"))
        locs = ", ".join(sorted({loc.country for loc in p.locations})) or p.hq_country
        table.add_row(
            p.id, Text(p.name, style="muted" if disabled else "bold"), p.hq_country, locs,
            ", ".join(f"AS{a}" for a in p.asns) or f"поиск: {p.asn_search}", p.size, str(p.popularity_ru), p.ip_type.upper(),
            flag_cell(p.trial, p.hints_only), flag_cell(p.hourly, p.hints_only), f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—", status,
            {"bundled": "ручная", "catalog": "каталог", "user": "своя", "discovered": "discovery"}.get(p.source, p.source),
        )
    _ = countries
    return table


def settings_overview(settings: Settings) -> Columns:
    def block(title: str, rows: list[tuple[str, object]]) -> Panel:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(style="muted")
        grid.add_column()
        for k, v in rows:
            grid.add_row(k, str(v))
        return Panel(grid, title=title, border_style="#243152", padding=(0, 1))

    s = settings
    return Columns(
        [
            block("Общие", [("язык", s.general.language), ("экспорт в", s.general.export_dir), ("форматы", ", ".join(s.general.default_exports)), ("на локацию", s.general.per_location), ("полная проверка", f"топ-{s.general.deep_per_location}"), ("потолок", s.general.max_candidates)]),
            block("Сеть", [("прокси", s.network.proxy or "—"), ("таймаут", f"{s.network.timeout_seconds:g} с"), ("ретраи", s.network.retries), ("параллельно", s.network.concurrency)]),
            block("Источники", [("cheburcheck", "вкл" if s.sources.cheburcheck.enabled else "выкл"), ("RIPEstat", "вкл" if s.sources.ripestat.enabled else "выкл"), ("PeeringDB", "вкл" if s.sources.peeringdb.enabled else "выкл"), ("ip-api", "вкл" if s.sources.ipapi.enabled else "выкл"), ("списков", sum(1 for b in s.sources.blocklists if b.enabled))]),
            block("Живые пробы", [("включены", "да" if s.live_probe.enabled else "нет"), ("порты", ", ".join(map(str, s.live_probe.ports))), ("таймаут", f"{s.live_probe.timeout_seconds:g} с")]),
        ],
        equal=True,
        expand=True,
    )
