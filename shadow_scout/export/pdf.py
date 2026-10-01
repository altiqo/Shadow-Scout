"""PDF-отчёт (reportlab) с кириллическим шрифтом DejaVu, встроенным в пакет."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from shadow_scout import __version__
from shadow_scout.export.common import (
    PICK_COLUMNS,
    fmt_int,
    holder_label,
    pick_rows,
    picked_reports,
    summary_counts,
    yes_no,
)
from shadow_scout.models import VERDICT_COLORS, VERDICT_LABELS_RU, RiskReport, SearchResult
from shadow_scout.paths import FONTS_DIR
from shadow_scout.providers import load_countries

_FONT = "DejaVuSans"
_FONT_BOLD = "DejaVuSans-Bold"
_registered = False


def _register_fonts() -> None:
    global _registered
    if _registered:
        return
    pdfmetrics.registerFont(TTFont(_FONT, str(FONTS_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(FONTS_DIR / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFontFamily(_FONT, normal=_FONT, bold=_FONT_BOLD, italic=_FONT, boldItalic=_FONT_BOLD)
    _registered = True


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=_FONT_BOLD, fontSize=20, leading=24, alignment=TA_LEFT, spaceAfter=4),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontName=_FONT, fontSize=9, textColor=colors.HexColor("#555555"), spaceAfter=10),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=_FONT_BOLD, fontSize=13, spaceBefore=10, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=_FONT_BOLD, fontSize=10.5, spaceBefore=6, spaceAfter=3),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName=_FONT, fontSize=8.5, leading=11),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontName=_FONT, fontSize=7.5, leading=9.5),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontName=_FONT, fontSize=7.5, leading=9),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName=_FONT_BOLD, fontSize=7.5, leading=9),
        "cellh": ParagraphStyle("ch", parent=base["Normal"], fontName=_FONT_BOLD, fontSize=7.5, leading=9, textColor=colors.white),
        "foot": ParagraphStyle("f", parent=base["Normal"], fontName=_FONT, fontSize=7, textColor=colors.HexColor("#777777")),
    }


def _esc(text: object) -> str:
    return str(text if text is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _verdict_color(verdict: str) -> colors.Color:
    return colors.HexColor(VERDICT_COLORS.get(verdict, VERDICT_COLORS["unknown"]))


def _picks_table(result: SearchResult, st: dict[str, ParagraphStyle]) -> Table | None:
    """Лучшие по локациям: одна таблица, локации — строки-заголовки."""
    rows = pick_rows(result)
    if not rows:
        return None
    keys = ["rank", "provider", "cities", "asns", "ipv4", "blocked_share", "trial", "hourly", "price", "survivability", "verdict", "depth"]
    titles = dict(PICK_COLUMNS)
    data = [[Paragraph(titles[k], st["cellh"]) for k in keys]]
    spans: list[int] = []
    current = None
    for row in rows:
        if row["location"] != current:
            current = row["location"]
            spans.append(len(data))
            data.append([Paragraph(f"<b>{_esc(current)}</b>", st["cell"])] + [""] * (len(keys) - 1))
        data.append([Paragraph(_esc(row[k]), st["cellb"] if k == "provider" else st["cell"]) for k in keys])
    widths = [8, 50, 38, 34, 20, 18, 14, 14, 12, 16, 32, 16]
    table = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c7ccd6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for idx in spans:
        style += [("SPAN", (0, idx), (-1, idx)), ("BACKGROUND", (0, idx), (-1, idx), colors.HexColor("#dbe4ff"))]
    table.setStyle(TableStyle(style))
    return table


def _summary_table(result: SearchResult, st: dict[str, ParagraphStyle], limit: int | None = None) -> Table:
    countries = load_countries()
    head = ["#", "Провайдер", "Страны", "ASN", "IPv4", "В списках", "Тип", "Trial", "Почас.", "от €", "Выжив.", "Вердикт", "Увер."]
    data = [[Paragraph(h, st["cellh"]) for h in head]]
    reports = result.sorted_reports()
    if limit:
        reports = reports[:limit]
    for rank, r in enumerate(reports, start=1):
        p = r.provider
        locs = r.matched_locations or p.locations
        cc = ", ".join(sorted({countries.name(loc.country) for loc in locs})) or "—"
        data.append([
            Paragraph(str(rank), st["cell"]),
            Paragraph(f"<b>{_esc(p.name)}</b><br/>{_esc(p.website_domain() or '')}", st["cell"]),
            Paragraph(_esc(cc), st["cell"]),
            Paragraph(_esc(", ".join(f"AS{a.asn}" for a in r.asns) or "—"), st["cell"]),
            Paragraph(fmt_int(r.total_ipv4) if r.total_ipv4 else "—", st["cell"]),
            Paragraph(f"{r.blocked_share*100:.2f}%" if r.total_ipv4 else "—", st["cell"]),
            Paragraph(p.ip_type.upper(), st["cell"]),
            Paragraph(yes_no(p.trial, p.hints_only), st["cell"]),
            Paragraph(yes_no(p.hourly, p.hints_only), st["cell"]),
            Paragraph(f"{p.min_price_eur:g}" if p.min_price_eur is not None else "—", st["cell"]),
            Paragraph(f"<b>{r.survivability:.0f}</b>", st["cell"]),
            Paragraph(VERDICT_LABELS_RU.get(r.verdict, r.verdict), st["cellb"]),
            Paragraph(f"{r.confidence*100:.0f}%", st["cell"]),
        ])
    widths = [8, 40, 42, 24, 18, 18, 15, 12, 15, 11, 14, 30, 14]
    table = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c7ccd6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]
    for idx, r in enumerate(reports, start=1):
        style.append(("BACKGROUND", (11, idx), (11, idx), _verdict_color(r.verdict)))
        style.append(("TEXTCOLOR", (11, idx), (11, idx), colors.white if r.verdict in ("critical", "high") else colors.black))
    table.setStyle(TableStyle(style))
    return table


def _provider_block(rank: int, r: RiskReport, st: dict[str, ParagraphStyle]) -> list:
    countries = load_countries()
    p = r.provider
    locs = r.matched_locations or p.locations
    loc_text = ", ".join(sorted({countries.name(loc.country) + (f" / {loc.city}" if loc.city else "") for loc in locs})) or "—"
    items: list = []
    head = Table(
        [[Paragraph(f"#{rank} {_esc(p.name)}", st["h3"]), Paragraph(f"<b>{VERDICT_LABELS_RU.get(r.verdict, r.verdict)}</b> · выживаемость {r.survivability:.0f}/100 · уверенность {r.confidence*100:.0f}%", st["cellb"])]],
        colWidths=[120 * mm, 150 * mm],
    )
    head.setStyle(TableStyle([
        ("BACKGROUND", (1, 0), (1, 0), _verdict_color(r.verdict)),
        ("TEXTCOLOR", (1, 0), (1, 0), colors.white if r.verdict in ("critical", "high") else colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    items.append(head)
    facts = [
        f"Сайт: {_esc(p.website or '—')} · Локации: {_esc(loc_text)}",
        f"Тип IP (база): {p.ip_type.upper()} · размер: {p.size} · популярность в RU: {p.popularity_ru}/5 · Trial: {yes_no(p.trial, p.hints_only)} · почасовая: {yes_no(p.hourly, p.hints_only)} · от {f'{p.min_price_eur:g} €' if p.min_price_eur is not None else '—'} · оплата: {_esc(', '.join(p.payment) or '—')}",
    ]
    if p.notes:
        facts.append(f"Примечание: {_esc(p.notes)}")
    for a in r.asns:
        line = f"AS{a.asn} — {_esc(holder_label(r, a.holder))}: IPv4 {fmt_int(a.ipv4_count)}, префиксов {len(a.prefixes_v4)}, в списках {a.blocked_share:.2%}"
        if a.peeringdb:
            line += f"; PeeringDB: {_esc(', '.join(a.peeringdb.get('info_types') or []) or '—')}, трафик {_esc(a.peeringdb.get('info_traffic') or '—')}"
        if a.blocked_prefixes:
            line += f"; заблокированные: {_esc(', '.join(a.blocked_prefixes[:6]))}{' …' if len(a.blocked_prefixes) > 6 else ''}"
        if a.holder_matches_provider is False:
            line += " (holder не совпадает с названием — проверьте ASN)"
        facts.append(line)
    for f in facts:
        items.append(Paragraph(f, st["body"]))
    if r.hard_flags:
        items.append(Paragraph("<b>Флаги:</b> " + _esc("; ".join(r.hard_flags)), st["body"]))
    if r.warnings:
        items.append(Paragraph("<b>Предупреждения:</b> " + _esc("; ".join(r.warnings)), st["small"]))
    sig_data = [[Paragraph("Сигнал", st["cellb"]), Paragraph("Риск", st["cellb"]), Paragraph("Вес", st["cellb"]), Paragraph("Описание", st["cellb"])]]
    for s in r.signals:
        sig_data.append([
            Paragraph(_esc(s.title), st["cell"]),
            Paragraph(f"{s.risk*100:.0f}" if s.risk is not None else "—", st["cell"]),
            Paragraph(f"{s.weight:g}", st["cell"]),
            Paragraph(_esc(s.summary), st["cell"]),
        ])
    sig_table = Table(sig_data, colWidths=[58 * mm, 12 * mm, 10 * mm, 190 * mm], repeatRows=1)
    sig_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for idx, s in enumerate(r.signals, start=1):
        if s.risk is None:
            sig_style.append(("TEXTCOLOR", (0, idx), (-1, idx), colors.HexColor("#888888")))
        else:
            sev = s.severity
            sig_style.append(("BACKGROUND", (1, idx), (1, idx), _verdict_color(sev)))
    sig_table.setStyle(TableStyle(sig_style))
    items.append(Spacer(1, 3))
    items.append(sig_table)
    items.append(Spacer(1, 3))
    items.append(Paragraph("<b>Рекомендации:</b>", st["body"]))
    for rec in r.recommendations:
        items.append(Paragraph("• " + _esc(rec), st["body"]))
    items.append(Spacer(1, 8))
    return [KeepTogether(items[:3])] + items[3:]


def write_pdf(result: SearchResult, path: Path) -> None:
    _register_fonts()
    st = _styles()
    doc = SimpleDocTemplate(
        str(path), pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm, bottomMargin=12 * mm,
        title=result.title, author=f"Shadow Scout {__version__}",
    )
    counts = summary_counts(result)
    story: list = [
        Paragraph(f"Shadow Scout · {_esc(result.title)}", st["title"]),
        Paragraph(
            f"Создан {result.generated_at.strftime('%d.%m.%Y %H:%M UTC')} · запрос: {_esc(result.query.describe())} · провайдеров: {len(result.reports)} · "
            f"низкий {counts['low']} / умеренный {counts['moderate']} / высокий {counts['high']} / критический {counts['critical']} / нет данных {counts['unknown']}",
            st["sub"],
        ),
    ]
    picks = _picks_table(result, st)
    if picks is not None:
        story += [Paragraph("Лучшие по локациям", st["h2"]), picks, Spacer(1, 6), PageBreak()]
    overall_limit = 60 if picks is not None else None
    story += [
        Paragraph("Все проанализированные провайдеры" + (f" (первые {overall_limit} по выживаемости)" if overall_limit and len(result.reports) > overall_limit else ""), st["h2"]),
        _summary_table(result, st, overall_limit),
        Spacer(1, 6),
        Paragraph("Выживаемость = 100 − риск. Оценка вероятностная: чистый IP не защищает от DPI-блокировок протоколов. Перед оплатой проверьте выданный IP на cheburcheck.ru.", st["small"]),
        PageBreak(),
        Paragraph("Подробности по провайдерам" + (" (только вошедшие в «лучшие по локациям»)" if picks is not None else ""), st["h2"]),
    ]
    details = picked_reports(result) if picks is not None else result.sorted_reports()
    for rank, r in enumerate(details, start=1):
        story.extend(_provider_block(rank, r, st))
    story.append(Paragraph("Источники данных", st["h2"]))
    for s in result.sources:
        story.append(Paragraph(f"{'●' if s.ok else '○'} {_esc(s.name)}: {_esc(s.detail)}", st["small"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Shadow Scout v{__version__}", st["foot"]))

    def footer(canvas, doc_) -> None:
        canvas.saveState()
        canvas.setFont(_FONT, 7)
        canvas.setFillColor(colors.HexColor("#777777"))
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 7 * mm, f"Shadow Scout · стр. {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
