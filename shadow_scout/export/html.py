"""Самодостаточный HTML-отчёт: сводка, сортируемая таблица, раскрывающиеся карточки провайдеров."""

from __future__ import annotations

import html
from pathlib import Path

from shadow_scout import __version__
from shadow_scout.export.common import (
    DEPTH_LABELS,
    fmt_int,
    holder_label,
    location_title,
    summary_counts,
    yes_no,
)
from shadow_scout.models import VERDICT_COLORS, VERDICT_LABELS_RU, RiskReport, SearchResult
from shadow_scout.providers import load_countries

CSS = """
:root{--bg:#0b1020;--panel:#121a2e;--panel2:#18223a;--text:#e5e9f3;--muted:#8d9bbd;--line:#243152;--accent:#7c9cff;
--low:#22c55e;--moderate:#eab308;--high:#f97316;--critical:#ef4444;--unknown:#94a3b8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,Inter,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:28px;margin:0 0 4px;letter-spacing:.3px}h1 span{color:var(--accent)}
.sub{color:var(--muted);margin-bottom:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card b{display:block;font-size:26px;line-height:1.1}.card small{color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
th{background:var(--panel2);color:var(--muted);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0}
th:hover{color:var(--text)}tr:hover td{background:rgba(124,156,255,.06)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;color:#0b1020;white-space:nowrap}
.bar{height:8px;border-radius:999px;background:#1e2a48;overflow:hidden;min-width:90px}.bar i{display:block;height:100%}
.score{display:flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums}
details{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:12px 0;padding:0 16px}
summary{cursor:pointer;padding:14px 0;font-weight:600;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
summary .meta{color:var(--muted);font-weight:400;font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 0 16px}@media(max-width:900px){.grid{grid-template-columns:1fr}}
.sig{display:grid;grid-template-columns:200px 60px 1fr;gap:10px;padding:7px 0;border-top:1px dashed var(--line);font-size:13px}
.sig:first-child{border-top:0}.sig b{font-weight:600}.sig .r{text-align:center;font-weight:700}
.sig.unavailable{color:var(--muted)}
ul{margin:6px 0 0 18px;padding:0}li{margin:4px 0}
.warn{color:#fbbf24}.flag{color:var(--critical);font-weight:600}
.src{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.src span{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:4px 10px;font-size:12.5px}
.ok{color:var(--low)}.bad{color:var(--high)}
footer{color:var(--muted);font-size:12.5px;margin-top:30px}
input.filter{background:var(--panel2);border:1px solid var(--line);color:var(--text);padding:8px 12px;border-radius:8px;width:320px;margin:0 0 12px}
a{color:var(--accent)}
.loc{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:10px 0;padding:0 14px}
.loc>summary{padding:12px 0}.loc table{border:0;background:transparent;margin-bottom:12px}
.loc .note{color:var(--muted);font-weight:400;font-size:13px}
.hint{color:var(--moderate)}.unk{color:var(--muted)}
@media print{body{background:#fff;color:#111}.card,table,details{background:#fff;border-color:#ccc}th{background:#eee;color:#333}}
"""

JS = """
document.querySelectorAll('th[data-k]').forEach(th=>th.addEventListener('click',()=>{
 const t=th.closest('table'),tb=t.querySelector('tbody'),i=[...th.parentNode.children].indexOf(th);
 const num=th.dataset.k==='num';const dir=th.dataset.dir==='asc'?'desc':'asc';th.dataset.dir=dir;
 const rows=[...tb.querySelectorAll('tr')];rows.sort((a,b)=>{let x=a.children[i].dataset.v??a.children[i].textContent,y=b.children[i].dataset.v??b.children[i].textContent;
 if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return dir==='asc'?x-y:y-x}return dir==='asc'?x.localeCompare(y):y.localeCompare(x)});
 rows.forEach(r=>tb.appendChild(r));}));
const f=document.getElementById('filter');if(f){f.addEventListener('input',()=>{const q=f.value.toLowerCase();
 document.querySelectorAll('tbody tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none');
 document.querySelectorAll('details[data-name]').forEach(d=>d.style.display=d.dataset.name.includes(q)?'':'none');});}
"""


def _e(text: object) -> str:
    return html.escape(str(text) if text is not None else "")


def _badge(verdict: str) -> str:
    color = VERDICT_COLORS.get(verdict, VERDICT_COLORS["unknown"])
    return f'<span class="badge" style="background:{color}">{_e(VERDICT_LABELS_RU.get(verdict, verdict))}</span>'


def _score_cell(report: RiskReport) -> str:
    color = VERDICT_COLORS.get(report.verdict, VERDICT_COLORS["unknown"])
    return (
        f'<div class="score"><div class="bar"><i style="width:{report.survivability:.0f}%;background:{color}"></i></div>'
        f"<b>{report.survivability:.0f}</b></div>"
    )


def _flag(value: bool | None, hint: bool) -> str:
    """✓ подтверждено · ~ определено автоматически · ? неизвестно · — нет."""
    if value is None:
        return '<span class="unk" title="неизвестно">?</span>'
    if not value:
        return '<span class="unk">—</span>'
    return '<span class="hint" title="определено автоматически, проверьте на сайте">~</span>' if hint else '<span class="ok">✓</span>'


def _picks_section(result: SearchResult) -> str:
    """Главный раздел отчёта: лучшие провайдеры по каждой локации."""
    if not result.picks:
        return ""
    blocks = []
    for n, pick in enumerate(result.picks):
        rows = []
        for rank, pid in enumerate(pick.provider_ids, start=1):
            r = result.report_by_id(pid)
            if r is None:
                continue
            p = r.provider
            cities = ", ".join(sorted({loc.city for loc in p.locations if loc.country == pick.country and loc.city})) or "—"
            auto = ' <small class="unk">[авто]</small>' if p.source == "catalog" else ""
            rows.append(
                "<tr>"
                f"<td>{rank}</td>"
                f"<td><a href='#p-{_e(p.id)}'><b>{_e(p.name)}</b></a>{auto}"
                + (f"<br><a href='{_e(p.website)}' target='_blank' rel='noopener'><small>{_e(p.website_domain())}</small></a>" if p.website else "")
                + "</td>"
                f"<td>{_e(cities)}</td>"
                f"<td>{_e(', '.join(f'AS{a.asn}' for a in r.asns) or '—')}</td>"
                f"<td>{fmt_int(r.total_ipv4) if r.total_ipv4 else '—'}</td>"
                f"<td>{(f'{r.blocked_share*100:.2f}%' if r.total_ipv4 else '—')}</td>"
                f"<td>{_flag(p.trial, p.hints_only)}</td><td>{_flag(p.hourly, p.hints_only)}</td>"
                f"<td>{_e(f'{p.min_price_eur:g}' if p.min_price_eur is not None else '—')}</td>"
                f"<td>{_score_cell(r)}</td><td>{_badge(r.verdict)}</td>"
                f"<td title='{_e(DEPTH_LABELS.get(r.depth, r.depth))} проверка'>{'●' if r.depth == 'full' else '◐'}</td>"
                "</tr>"
            )
        if not rows:
            reason = "в базе нет подходящих провайдеров" if not pick.candidates else "рекомендовать некого: все проанализированные критичны или без данных"
            rows.append(f"<tr><td colspan='12' class='warn'>{reason}</td></tr>")
        blocks.append(
            f"<details class='loc'{' open' if n < 6 else ''} data-name='{_e(location_title(pick.country, pick.city).lower())}'>"
            f"<summary>{_e(location_title(pick.country, pick.city))} "
            f"<span class='note'>в базе подошло {pick.candidates}, проанализировано {pick.analyzed}</span></summary>"
            "<table><thead><tr><th>#</th><th>Провайдер</th><th>Город</th><th>ASN</th><th>IPv4</th><th>В списках</th>"
            "<th>Trial</th><th>Почас.</th><th>от €</th><th>Выживаемость</th><th>Вердикт</th><th>Пров.</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></details>"
        )
    return (
        "<h2>Лучшие по локациям</h2>"
        "<div class='sub'>● полная проверка (cheburcheck и др.) · ◐ быстрая (локальные списки) · "
        "Trial/почасовая: ✓ подтверждено, ~ определено автоматически, ? неизвестно. "
        "Один провайдер показан не более чем в нескольких локациях, пока есть альтернативы.</div>"
        + "".join(blocks)
    )


def _provider_card(rank: int, report: RiskReport, open_: bool = False) -> str:
    countries = load_countries()
    p = report.provider
    locs = report.matched_locations or p.locations
    loc_text = ", ".join(sorted({countries.name(loc.country) + (f" / {loc.city}" if loc.city else "") for loc in locs})) or "—"
    asn_lines = "".join(
        f"<li><b>AS{a.asn}</b> — {_e(holder_label(report, a.holder))}"
        + (' <span class="warn">(holder не совпадает с названием)</span>' if a.holder_matches_provider is False else "")
        + f"<br><small>IPv4: {fmt_int(a.ipv4_count)} · префиксов: {len(a.prefixes_v4)} · в списках: {a.blocked_share:.2%}"
        + (f" · PeeringDB: {_e(', '.join(a.peeringdb.get('info_types') or []) or '—')}, трафик {_e(a.peeringdb.get('info_traffic') or '—')}" if a.peeringdb else "")
        + (f"<br>Заблокированные префиксы: {_e(', '.join(a.blocked_prefixes[:8]))}{' …' if len(a.blocked_prefixes) > 8 else ''}" if a.blocked_prefixes else "")
        + "</small></li>"
        for a in report.asns
    ) or "<li>ASN не определён</li>"
    sig_rows = "".join(
        f'<div class="sig {s.status.value}"><b>{_e(s.title)}</b><span class="r">{(f"{s.risk*100:.0f}" if s.risk is not None else "—")}</span><span>{_e(s.summary)}</span></div>'
        for s in report.signals
    )
    flags = "".join(f'<li class="flag">{_e(f)}</li>' for f in report.hard_flags)
    warns = "".join(f'<li class="warn">{_e(w)}</li>' for w in report.warnings)
    recs = "".join(f"<li>{_e(r)}</li>" for r in report.recommendations)
    facts = (
        f"<li>Сайт: <a href=\"{_e(p.website)}\" target=\"_blank\" rel=\"noopener\">{_e(p.website)}</a></li>" if p.website else ""
    ) + (
        f"<li>Локации: {_e(loc_text)}</li>"
        f"<li>Тип IP (база): {_e(p.ip_type.upper())} · размер: {_e(p.size)} · популярность в RU: {p.popularity_ru}/5</li>"
        f"<li>Trial: {yes_no(p.trial, p.hints_only)}{(' — ' + _e(p.trial_note)) if p.trial_note else ''} · почасовая: {yes_no(p.hourly, p.hints_only)} · от {_e(f'{p.min_price_eur:g} €' if p.min_price_eur is not None else '—')}</li>"
        f"<li>Оплата: {_e(', '.join(p.payment) or '—')}</li>"
        + (f"<li>Примечание: {_e(p.notes)}</li>" if p.notes else "")
    )
    return (
        f'<details id="p-{_e(p.id)}" data-name="{_e(p.name.lower())}"{" open" if open_ else ""}><summary>#{rank} {_e(p.name)} {_badge(report.verdict)}'
        f'<span class="meta">выживаемость {report.survivability:.0f}/100 · уверенность {report.confidence*100:.0f}% · {_e(loc_text)}</span></summary>'
        f'<div class="grid"><div><h4>Провайдер</h4><ul>{facts}</ul><h4>Сети</h4><ul>{asn_lines}</ul>'
        + (f"<h4>Флаги</h4><ul>{flags}</ul>" if flags else "")
        + (f"<h4>Предупреждения</h4><ul>{warns}</ul>" if warns else "")
        + f"</div><div><h4>Сигналы риска (0 — безопасно, 100 — максимум)</h4>{sig_rows}<h4>Рекомендации</h4><ul>{recs}</ul></div></div></details>"
    )


def write_html(result: SearchResult, path: Path) -> None:
    countries = load_countries()
    reports = result.sorted_reports()
    counts = summary_counts(result)
    rows = []
    for rank, r in enumerate(reports, start=1):
        p = r.provider
        locs = r.matched_locations or p.locations
        cc = ", ".join(sorted({countries.name(loc.country) for loc in locs})) or "—"
        rows.append(
            "<tr>"
            f"<td data-v='{rank}'>{rank}</td>"
            f"<td><b>{_e(p.name)}</b>" + (f"<br><a href='{_e(p.website)}' target='_blank' rel='noopener'><small>{_e(p.website_domain())}</small></a>" if p.website else "") + "</td>"
            f"<td>{_e(cc)}</td>"
            f"<td>{_e(', '.join(f'AS{a.asn}' for a in r.asns) or '—')}</td>"
            f"<td data-v='{r.total_ipv4}'>{fmt_int(r.total_ipv4) if r.total_ipv4 else '—'}</td>"
            f"<td data-v='{r.blocked_share*100:.3f}'>{(f'{r.blocked_share*100:.2f}%' if r.total_ipv4 else '—')}</td>"
            f"<td>{_e(p.ip_type.upper())}</td>"
            f"<td>{_flag(p.trial, p.hints_only)}</td><td>{_flag(p.hourly, p.hints_only)}</td>"
            f"<td data-v='{p.min_price_eur if p.min_price_eur is not None else 9999}'>{_e(f'{p.min_price_eur:g}' if p.min_price_eur is not None else '—')}</td>"
            f"<td data-v='{r.survivability}'>{_score_cell(r)}</td>"
            f"<td data-v='{r.risk_score}'>{_badge(r.verdict)}</td>"
            f"<td data-v='{r.confidence}'>{r.confidence*100:.0f}%</td>"
            "</tr>"
        )
    cards = "".join(_provider_card(i, r, open_=i <= 3) for i, r in enumerate(reports, start=1))
    sources = "".join(
        f"<span class='{'ok' if s.ok else 'bad'}'>{'●' if s.ok else '○'} {_e(s.name)}: {_e(s.detail)}</span>" for s in result.sources
    )
    doc = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(result.title)}</title><style>{CSS}</style></head><body><div class="wrap">
<h1><span>Shadow Scout</span> · {_e(result.title)}</h1>
<div class="sub">Создан {result.generated_at.strftime('%d.%m.%Y %H:%M UTC')} · запрос: {_e(result.query.describe())} · проанализировано {len(reports)} из {result.candidates_total or len(reports)} подходящих · {result.duration_seconds:.0f} с</div>
<div class="cards">
<div class="card"><b style="color:var(--low)">{counts['low']}</b><small>низкий риск</small></div>
<div class="card"><b style="color:var(--moderate)">{counts['moderate']}</b><small>умеренный</small></div>
<div class="card"><b style="color:var(--high)">{counts['high']}</b><small>высокий</small></div>
<div class="card"><b style="color:var(--critical)">{counts['critical']}</b><small>критический</small></div>
<div class="card"><b style="color:var(--unknown)">{counts['unknown']}</b><small>нет данных</small></div>
</div>
{_picks_section(result)}
<h2>Все проанализированные провайдеры</h2>
<input id="filter" class="filter" placeholder="Фильтр по названию, стране, ASN…">
<table><thead><tr>
<th data-k="num">#</th><th data-k="str">Провайдер</th><th data-k="str">Страны</th><th data-k="str">ASN</th><th data-k="num">IPv4</th>
<th data-k="num">В списках</th><th data-k="str">Тип IP</th><th data-k="str">Trial</th><th data-k="str">Почас.</th><th data-k="num">от €</th>
<th data-k="num">Выживаемость</th><th data-k="num">Вердикт</th><th data-k="num">Увер.</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Подробности по провайдерам</h2>{cards}
<h2>Источники данных</h2><div class="src">{sources}</div>
<footer>Shadow Scout v{__version__}. Оценка — вероятностная: «чистый» IP не защищает от DPI-блокировок протоколов. Проверяйте выданный IP на cheburcheck.ru перед оплатой.</footer>
</div><script>{JS}</script></body></html>"""
    path.write_text(doc, encoding="utf-8")
