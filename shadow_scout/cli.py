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
    trial: bool = typer.Option(False, "--trial", help="Только с бесплатным trial"),
    hourly: bool = typer.Option(False, "--hourly", help="Только с почасовой оплатой"),
    max_price: float | None = typer.Option(None, "--max-price", help="Максимальная цена, €/мес"),
    ip_type: str | None = typer.Option(None, "--ip-type", help="isp | dch | any"),
    max_asn: int | None = typer.Option(None, "--max-asn", help="Максимум IPv4-адресов в ASN"),
    include_large: bool = typer.Option(False, "--include-large", help="Включить крупные хостинги"),
    include_ru: bool = typer.Option(False, "--include-ru", help="Включить провайдеров со связями с РФ"),
    max_risk: str | None = typer.Option(None, "--max-risk", help="low | moderate | high"),
    live: bool = typer.Option(False, "--live", help="Живые TCP-пробы"),
    limit: int = typer.Option(25, "--limit", "-n", help="Сколько провайдеров анализировать"),
    export: str | None = typer.Option(None, "--export", "-e", help="Форматы через запятую: html,pdf,xlsx,csv,md,json"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Папка для отчётов"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Без живого прогресса"),
) -> None:
    """Поиск и оценка провайдеров по фильтрам."""
    from shadow_scout.runner import run_search

    settings = get_settings()
    countries = load_countries()
    codes = [c.upper() for c in (country or [])]
    if low_radar:
        codes = list(dict.fromkeys(codes + countries.low_radar_codes()))
    query = SearchQuery(
        countries=codes, require_trial=trial, require_hourly=hourly, max_price_eur=max_price,
        ip_type=["isp", "mixed"] if ip_type == "isp" else (["dch"] if ip_type == "dch" else []),
        max_asn_ipv4=max_asn, max_size=None if include_large else "medium", max_risk=max_risk, include_ru_ties=include_ru,
        live_probe=live, limit=limit,
    )
    db = ProviderDB()
    providers = db.filter(query)
    providers = sorted(providers, key=lambda p: (p.popularity_ru, p.name))[:limit]
    if not providers:
        console.print("[warn]Нет провайдеров под такие фильтры.[/warn]")
        raise typer.Exit(1)
    if not quiet:
        console.print(banner())
        console.print(f"[muted]Запрос:[/muted] {query.describe()} · кандидатов: {len(providers)}")
    result = run_search(settings, providers, query, title="Поиск VPS: " + (", ".join(codes) if codes else "все страны"), quiet=quiet)
    if max_asn:
        result.reports = [r for r in result.reports if not r.total_ipv4 or r.total_ipv4 <= max_asn]
    console.print(views.summary_line(result))
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
        result = run_search(settings, providers, SearchQuery(countries=[country.upper()], include_ru_ties=True), title=f"Discovery {country.upper()}", quiet=quiet)
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
def providers_cmd(country: str | None = typer.Option(None, "--country", "-c"), all_: bool = typer.Option(False, "--all", help="Включая отключённых")) -> None:
    """Показать базу провайдеров."""
    db = ProviderDB()
    providers = db.all(include_disabled=all_)
    if country:
        providers = [p for p in providers if country.upper() in p.countries]
    console.print(views.providers_table(db, providers))


@app.command("paths")
def paths_cmd() -> None:
    """Показать пути конфига, кеша и пользовательской базы."""
    console.print(f"конфиг:  {config_file()}\nкеш:     {cache_dir()}\nбаза:    {user_providers_file()}")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Прервано.[/muted]")
        sys.exit(130)


if __name__ == "__main__":
    main()
