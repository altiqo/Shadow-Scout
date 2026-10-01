"""CLI (typer): без аргументов — интерактивное меню; подкоманды — для скриптов и быстрых проверок."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from shadow_scout import __version__
from shadow_scout.config import get_settings
from shadow_scout.export import FORMATS
from shadow_scout.models import SearchQuery
from shadow_scout.paths import cache_dir, config_file, user_providers_file
from shadow_scout.providers import ProviderDB, load_countries
from shadow_scout.ui import views
from shadow_scout.ui.theme import banner, console

app = typer.Typer(add_completion=False, no_args_is_help=False, help="Shadow Scout — поиск VPS под VPN вне радара РКН.", rich_markup_mode="rich")


def _parse_formats(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return default
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        raise typer.BadParameter(f"неизвестные форматы: {', '.join(bad)}; доступны: {', '.join(FORMATS)}")
    return formats


def _export_and_print(result, formats: list[str], out: Path | None) -> None:
    from shadow_scout.runner import do_export

    settings = get_settings()
    if not formats:
        return
    for path in do_export(result, formats, out, settings):
        console.print(f"[ok]✔[/ok] {path}")


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context, version: bool = typer.Option(False, "--version", "-V", help="Показать версию")) -> None:
    if version:
        console.print(f"Shadow Scout {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        from shadow_scout.ui.menu import run_menu

        run_menu(get_settings())


@app.command()
def search(
    country: list[str] = typer.Option(None, "--country", "-c", help="Код страны (можно несколько: -c SE -c FI)"),
    low_radar: bool = typer.Option(False, "--low-radar", help="Все страны с низким радаром"),
    trial: bool = typer.Option(False, "--trial", help="Нужен бесплатный trial"),
    hourly: bool = typer.Option(False, "--hourly", help="Нужна почасовая оплата"),
    strict: bool = typer.Option(False, "--strict", help="trial/почасовая — только подтверждённые (иначе «неизвестно» тоже подходит)"),
    max_price: float | None = typer.Option(None, "--max-price", help="Максимальная цена, €/мес"),
    ip_type: str | None = typer.Option(None, "--ip-type", help="isp | dch | any"),
    max_asn: int | None = typer.Option(None, "--max-asn", help="Максимум IPv4-адресов в ASN"),
    include_large: bool = typer.Option(False, "--include-large", help="Включить крупные хостинги"),
    include_ru: bool = typer.Option(False, "--include-ru", help="Включить провайдеров со связями с РФ"),
    max_risk: str | None = typer.Option(None, "--max-risk", help="low | moderate | high"),
    live: bool = typer.Option(False, "--live", help="Живые TCP-пробы"),
    per_location: int | None = typer.Option(None, "--per-location", "-k", help="Сколько лучших показать на каждую локацию"),
    deep: int | None = typer.Option(None, "--deep", help="У скольких лучших на локацию делать полную проверку (cheburcheck); 0 — только быстрая"),
    limit: int | None = typer.Option(None, "--limit", "-n", help="Потолок числа анализируемых провайдеров (делится между локациями)"),
    by_city: bool = typer.Option(False, "--by-city", help="Группировать по городам, а не по странам"),
    max_repeat: int = typer.Option(1, "--max-repeat", help="В скольких локациях один провайдер может быть в «лучших», пока есть альтернативы (0 — без ограничения)"),
    verified_only: bool = typer.Option(False, "--verified-only", help="Только провайдеры с подтверждённым VPS"),
    no_catalog: bool = typer.Option(False, "--no-catalog", help="Только ручная база, без автокаталога"),
    table: bool = typer.Option(False, "--table", help="Вывести и общую таблицу всех проанализированных провайдеров"),
    export: str | None = typer.Option(None, "--export", "-e", help="Форматы через запятую: html,pdf,xlsx,csv,md,json"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Папка для отчётов"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Без живого прогресса"),
) -> None:
    """Поиск и оценка провайдеров: лучшие варианты на каждую локацию."""
    from shadow_scout.runner import plan_search, run_search

    settings = get_settings()
    countries = load_countries()
    codes = [c.upper() for c in (country or [])]
    if low_radar:
        codes = list(dict.fromkeys(codes + countries.low_radar_codes()))
    query = SearchQuery(
        countries=codes, require_trial=trial, require_hourly=hourly, max_price_eur=max_price,
        ip_type=["isp", "mixed"] if ip_type == "isp" else (["dch"] if ip_type == "dch" else []),
        max_asn_ipv4=max_asn, max_size=None if include_large else "medium", max_risk=max_risk, include_ru_ties=include_ru,
        live_probe=live, limit=limit or settings.general.max_candidates,
        per_location=per_location or settings.general.per_location,
        deep_per_location=settings.general.deep_per_location if deep is None else deep,
        group_by="city" if by_city else "country", max_repeat=max_repeat, strict_flags=strict,
        include_unverified=not verified_only, use_catalog=not no_catalog,
    )
    db = ProviderDB()
    plan = plan_search(db, query)
    if not plan.candidates:
        console.print("[warn]Нет провайдеров под такие фильтры.[/warn]")
        raise typer.Exit(1)
    if not quiet:
        console.print(banner())
        console.print(f"[muted]Запрос:[/muted] {query.describe()}")
        console.print(views.plan_line(plan))
    result = run_search(settings, plan.candidates, query, title="Поиск VPS: " + (", ".join(codes) if codes else "все страны"), quiet=quiet, plan=plan)
    console.print(views.summary_line(result))
    console.print(views.picks_view(result))
    if table:
        console.print(views.results_table(result))
    console.print(views.sources_panel(result.sources))
    _export_and_print(result, _parse_formats(export, []), out)


@app.command()
def check(
    target: str = typer.Argument(..., help="AS12345, IP, домен или id провайдера из базы"),
    live: bool = typer.Option(False, "--live", help="Живые TCP-пробы"),
    export: str | None = typer.Option(None, "--export", "-e", help="Форматы через запятую"),
    out: Path | None = typer.Option(None, "--out", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Проверить один провайдер / ASN / IP / домен."""
    from shadow_scout.runner import run_check

    settings = get_settings()
    db = ProviderDB()
    provider = db.get(target)
    result = run_check(settings, target=None if provider else target, provider=provider, live=live, quiet=quiet)
    console.print(views.report_panel(result.reports[0]))
    console.print(views.sources_panel(result.sources))
    _export_and_print(result, _parse_formats(export, []), out)


@app.command()
def verify(
    ips: list[str] = typer.Argument(..., help="Выданный хостером IP (можно несколько)"),
    live: bool = typer.Option(False, "--live", help="Проверить достижимость с этой машины (TCP-пробы)"),
    ports: str = typer.Option("22,443", "--ports", help="Порты для проб через запятую"),
    sni: str | None = typer.Option(None, "--sni", help="Дополнительно проверить TLS-рукопожатие с этим SNI (напр. www.microsoft.com)"),
    json_out: Path | None = typer.Option(None, "--json", help="Сохранить результат в JSON-файл"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Проверить конкретный IP после выдачи сервера: он и его подсеть в списках, cheburcheck, достижимость."""
    from shadow_scout.runner import run_verify

    try:
        port_list = [int(p) for p in ports.split(",") if p.strip()]
    except ValueError as exc:
        raise typer.BadParameter("порты — числа через запятую") from exc
    try:
        reports = run_verify(get_settings(), ips, live=live or sni is not None, ports=port_list, sni=sni, quiet=quiet)
    except ValueError as exc:
        console.print(f"[bad]{exc}[/bad]")
        raise typer.Exit(2) from exc
    for report in reports:
        console.print(views.ip_report_panel(report))
    if json_out:
        import json

        json_out.write_text(json.dumps([r.model_dump(mode="json") for r in reports], ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[ok]✔[/ok] {json_out}")
    if any(r.verdict == "blocked" for r in reports):
        raise typer.Exit(3)  # удобно для скриптов: «купленный» IP заблокирован


@app.command()
def discover(
    country: str = typer.Argument(..., help="Код страны, напр. SE"),
    max_candidates: int = typer.Option(60, "--max", help="Сколько ASN анализировать"),
    keywords: bool = typer.Option(True, "--keywords/--no-keywords", help="Фильтр по ключевым словам"),
    max_ipv4: int = typer.Option(262144, "--max-ipv4", help="Максимальный размер сети"),
    analyze: bool = typer.Option(False, "--analyze", help="Полный анализ лучших кандидатов"),
    top: int = typer.Option(10, "--top", help="Сколько лучших анализировать при --analyze"),
    export: str | None = typer.Option(None, "--export", "-e"),
    out: Path | None = typer.Option(None, "--out", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Найти небольшие локальные ASN в стране."""
    from shadow_scout.analysis.discovery import DiscoveryOptions
    from shadow_scout.runner import run_discovery, run_search

    settings = get_settings()
    options = DiscoveryOptions(country=country.upper(), max_candidates=max_candidates, keyword_filter=keywords, max_ipv4=max_ipv4)
    candidates = run_discovery(settings, options, quiet=quiet)
    console.print(views.discovery_table(candidates))
    if analyze and candidates:
        providers = [c.to_provider() for c in candidates[:top]]
        # кандидатов выбирали вручную — проверяем полностью всех, а не только лучших на локацию
        query = SearchQuery(countries=[country.upper()], include_ru_ties=True, per_location=len(providers), deep_per_location=len(providers))
        result = run_search(settings, providers, query, title=f"Discovery {country.upper()}", quiet=quiet)
        console.print(views.results_table(result))
        _export_and_print(result, _parse_formats(export, []), out)


@app.command()
def update() -> None:
    """Обновить списки блокировок и таблицу ASN."""
    from shadow_scout.runner import update_lists

    for line in update_lists(get_settings()):
        console.print("  " + line)


@app.command("export")
def export_cmd(
    formats: str = typer.Option("html,pdf", "--format", "-f", help="Форматы через запятую"),
    out: Path | None = typer.Option(None, "--out", "-o"),
) -> None:
    """Экспортировать последний отчёт."""
    from shadow_scout.runner import load_last_result

    result = load_last_result()
    if result is None:
        console.print("[warn]Последнего отчёта нет.[/warn]")
        raise typer.Exit(1)
    _export_and_print(result, _parse_formats(formats, ["html", "pdf"]), out)


@app.command("providers")
def providers_cmd(
    country: str | None = typer.Option(None, "--country", "-c"),
    all_: bool = typer.Option(False, "--all", help="Включая отключённых"),
    source: str | None = typer.Option(None, "--source", help="curated | catalog | user"),
    stats: bool = typer.Option(False, "--stats", help="Сводка по странам: сколько провайдеров в каждой локации"),
) -> None:
    """Показать базу провайдеров."""
    db = ProviderDB()
    providers = db.all(include_disabled=all_)
    if country:
        providers = [p for p in providers if country.upper() in p.location_countries]
    if source:
        wanted = {"curated": {"bundled"}, "catalog": {"catalog"}, "user": {"user", "discovered"}}.get(source.lower())
        if wanted is None:
            raise typer.BadParameter("curated | catalog | user")
        providers = [p for p in providers if p.source in wanted]
    if stats:
        console.print(views.country_stats_table(db))
        return
    console.print(views.providers_table(db, providers))


@app.command("harvest")
def harvest_cmd(
    country: list[str] = typer.Option(None, "--country", "-c", help="Только эти страны (по умолчанию — все, кроме враждебных юрисдикций)"),
    no_web: bool = typer.Option(False, "--no-web", help="Не проверять сайты (быстрее, но без подтверждения VPS)"),
    no_blocklists: bool = typer.Option(False, "--no-blocklists", help="Не отбрасывать сети, уже занесённые в списки блокировок"),
    refresh: bool = typer.Option(False, "--refresh", help="Заново скачать выгрузку PeeringDB и таблицу ASN"),
    bundled: bool = typer.Option(False, "--bundled", help="Записать в каталог, поставляемый с программой (для разработчиков)"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Куда записать каталог (по умолчанию — пользовательский каталог данных)"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Собрать каталог хостинг-провайдеров из PeeringDB, RIPEstat и сайтов — база вырастает на сотни записей."""
    from shadow_scout.runner import run_harvest

    summary = run_harvest(get_settings(), countries=[c.upper() for c in (country or [])], web=not no_web, blocklists=not no_blocklists, refresh=refresh, bundled=bundled, out=out, quiet=quiet)
    for line in summary:
        console.print("  " + line)


@app.command("verify-db")
def verify_db_cmd(
    source: str = typer.Option("curated", "--source", help="curated | catalog | user | all"),
    country: str | None = typer.Option(None, "--country", "-c", help="Только провайдеры этой страны"),
    no_web: bool = typer.Option(False, "--no-web", help="Не открывать сайты (быстрее)"),
    level: str = typer.Option("warn", "--level", help="Минимальный уровень в выводе: error | warn | info"),
    json_out: Path | None = typer.Option(None, "--json", help="Сохранить все проблемы в JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Проверить саму базу провайдеров против живых данных: ASN, держатель, размер сети, сайт, заявленные условия."""
    from shadow_scout.runner import run_dbcheck

    db = ProviderDB()
    wanted = {"curated": {"bundled"}, "catalog": {"catalog"}, "user": {"user", "discovered"}, "all": None}.get(source.lower(), "bad")
    if wanted == "bad":
        raise typer.BadParameter("curated | catalog | user | all")
    providers = [p for p in db.all() if wanted is None or p.source in wanted]
    if country:
        providers = [p for p in providers if country.upper() in p.location_countries]
    if level not in ("error", "warn", "info"):
        raise typer.BadParameter("error | warn | info")
    issues = run_dbcheck(get_settings(), providers, web=not no_web, quiet=quiet)
    rank = {"error": 0, "warn": 1, "info": 2}
    shown = [i for i in issues if rank[i.level] <= rank[level]]
    console.print(f"[muted]Проверено записей: {len(providers)} · проблем: {sum(1 for i in issues if i.level == 'error')} ошибок, {sum(1 for i in issues if i.level == 'warn')} предупреждений, {sum(1 for i in issues if i.level == 'info')} замечаний[/muted]")
    if shown:
        console.print(views.dbcheck_table(shown))
    if json_out:
        import json

        json_out.write_text(json.dumps([i.model_dump() for i in issues], ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[ok]✔[/ok] {json_out}")
    if any(i.level == "error" for i in issues):
        raise typer.Exit(1)  # для CI: в базе есть ошибки


@app.command("paths")
def paths_cmd() -> None:
    """Показать пути конфига, кеша и пользовательской базы."""
    from shadow_scout.harvest.catalog_io import CATALOG_FILE, user_catalog_file

    console.print(f"конфиг:  {config_file()}\nкеш:     {cache_dir()}\nбаза:    {user_providers_file()}\nкаталог: {user_catalog_file()}  (поставляемый: {CATALOG_FILE})")


def _force_utf8_when_redirected() -> None:
    """При выводе в файл/pipe Windows берёт старую кодовую страницу и падает на «✖», «●», кириллице — переключаем на UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main() -> None:
    _force_utf8_when_redirected()
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Прервано.[/muted]")
        sys.exit(130)


if __name__ == "__main__":
    main()
