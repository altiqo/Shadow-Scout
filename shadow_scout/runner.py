"""Общая оркестрация для меню и CLI: подготовка сервисов, запуск поиска/проверки/discovery, экспорт, последний отчёт."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

from shadow_scout import selection
from shadow_scout.analysis.discovery import Candidate, DiscoveryEngine, DiscoveryOptions
from shadow_scout.analysis.engine import AnalysisEngine, ProgressHooks, Services
from shadow_scout.config import Settings
from shadow_scout.export import export_many
from shadow_scout.models import Provider, RiskReport, SearchQuery, SearchResult
from shadow_scout.paths import last_result_file
from shadow_scout.providers import ProviderDB
from shadow_scout.ui.progress import SearchProgress, StepProgress
from shadow_scout.ui.theme import console


def build_services(settings: Settings) -> Services:
    return Services.build(settings)


async def prepare(services: Services, force_lists: bool = False, quiet: bool = False) -> None:
    await services.http.start()
    if quiet:
        await services.ensure_blocklists(force=force_lists)
        return
    with StepProgress("Загрузка списков блокировок…") as step:
        await services.ensure_blocklists(force=force_lists, progress=step.update)


async def _run_search_async(
    services: Services, providers: list[Provider], query: SearchQuery, title: str, quiet: bool, plan: selection.Plan | None = None
) -> SearchResult:
    if quiet:
        engine = AnalysisEngine(services, ProgressHooks())
        return await engine.run_search(providers, query, title, plan=plan)
    with SearchProgress(len(providers)) as progress:
        engine = AnalysisEngine(services, progress.hooks())
        return await engine.run_search(providers, query, title, plan=plan)


def run_search(
    settings: Settings,
    providers: list[Provider],
    query: SearchQuery,
    title: str = "Поиск VPS",
    quiet: bool = False,
    force_lists: bool = False,
    plan: selection.Plan | None = None,
) -> SearchResult:
    async def main() -> SearchResult:
        services = build_services(settings)
        try:
            await prepare(services, force_lists=force_lists, quiet=quiet)
            result = await _run_search_async(services, providers, query, title, quiet, plan)
        finally:
            await services.http.close()
        return result

    result = asyncio.run(main())
    save_last_result(result)
    return result


def run_check(settings: Settings, target: str | None = None, provider: Provider | None = None, live: bool = False, quiet: bool = False) -> SearchResult:
    async def main() -> SearchResult:
        services = build_services(settings)
        try:
            await prepare(services, quiet=quiet)
            engine_quiet = AnalysisEngine(services)
            prov = provider or await engine_quiet.provider_from_target(target or "")
            query = SearchQuery(live_probe=live, include_ru_ties=True)
            if quiet:
                engine = AnalysisEngine(services)
                report = await engine.analyze(prov, query)
            else:
                with SearchProgress(1, "Проверка") as progress:
                    engine = AnalysisEngine(services, progress.hooks())
                    report = await engine.analyze(prov, query)
            return SearchResult(query=query, reports=[report], sources=services.source_statuses(), title=f"Проверка: {prov.name}", duration_seconds=report.duration_seconds)
        finally:
            await services.http.close()

    result = asyncio.run(main())
    save_last_result(result)
    return result


def run_discovery(settings: Settings, options: DiscoveryOptions, quiet: bool = False, on_candidate: Callable[[Candidate], None] | None = None) -> list[Candidate]:
    async def main() -> list[Candidate]:
        services = build_services(settings)
        try:
            await prepare(services, quiet=quiet)
            engine = DiscoveryEngine(services)
            if quiet:
                return await engine.discover(options, on_candidate=on_candidate)
            with StepProgress(f"Discovery {options.country.upper()}: сбор ASN…") as step:
                counter = {"n": 0}

                def hook(c: Candidate) -> None:
                    counter["n"] += 1
                    step.update(f"Discovery {options.country.upper()}: проанализировано {counter['n']} ASN (AS{c.asn})")
                    if on_candidate:
                        on_candidate(c)

                return await engine.discover(options, on_candidate=hook, log=lambda m: step.update(m))
        finally:
            await services.http.close()

    return asyncio.run(main())


def update_lists(settings: Settings) -> list[str]:
    async def main() -> list[str]:
        services = build_services(settings)
        try:
            await services.http.start()
            with StepProgress("Обновление списков блокировок…") as step:
                bundle = await services.ensure_blocklists(force=True, progress=step.update)
                step.update("Обновление таблицы ASN (ipverse)…")
                try:
                    await services.asn_names.load(force=True)
                    names_line = f"Таблица ASN: {len(await services.asn_names.load()):,} записей".replace(",", " ")
                except Exception as exc:  # noqa: BLE001
                    names_line = f"Таблица ASN: ошибка ({exc})"
            lines = bundle.summary().splitlines() + [names_line]
            status = await services.cheburcheck.status()
            if status:
                lines.append(f"cheburcheck.ru: доступен, доменов {status.get('domain_count')}, IPv4 {status.get('v4_count')}, обновлён {status.get('last_update')}")
            elif settings.sources.cheburcheck.enabled:
                lines.append("cheburcheck.ru: недоступен (проверьте сеть/прокси)")
            return lines
        finally:
            await services.http.close()

    return asyncio.run(main())


def run_verify(
    settings: Settings,
    ips: list[str],
    live: bool = False,
    ports: list[int] | None = None,
    sni: str | None = None,
    quiet: bool = False,
) -> list:
    """Проверяет конкретные IP-адреса (после выдачи сервера): списки, подсеть, cheburcheck, достижимость."""
    from shadow_scout.analysis.verify import verify_ip

    async def main() -> list:
        services = build_services(settings)
        try:
            await prepare(services, quiet=quiet)
            return [await verify_ip(services, ip, ports=ports, live=live, sni=sni, timeout=settings.live_probe.timeout_seconds + 1) for ip in ips]
        finally:
            await services.http.close()

    return asyncio.run(main())


def run_dbcheck(settings: Settings, providers: list[Provider], web: bool = True, quiet: bool = False) -> list:
    """Сверяет записи базы с живыми данными (ASN, держатель, размер, сайт, условия) и возвращает найденные проблемы."""
    from shadow_scout.analysis.dbcheck import check_database

    async def main() -> list:
        services = build_services(settings)
        try:
            await services.http.start()
            if quiet:
                return await check_database(services, providers, web=web)
            with StepProgress("Проверка базы…") as step:
                return await check_database(services, providers, web=web, progress=lambda done, total: step.update(f"Проверка базы: {done}/{total}"))
        finally:
            await services.http.close()

    return asyncio.run(main())


def run_harvest(
    settings: Settings,
    countries: list[str] | None = None,
    web: bool = True,
    blocklists: bool = True,
    refresh: bool = False,
    bundled: bool = False,
    out: Path | None = None,
    quiet: bool = False,
) -> list[str]:
    """Собирает каталог провайдеров (PeeringDB + имена ASN + сайты) и сохраняет его; возвращает строки сводки."""
    from collections import Counter

    from shadow_scout.harvest.build import CatalogOverrides, HarvestOptions, harvest
    from shadow_scout.harvest.catalog_io import CATALOG_FILE, user_catalog_file, write_catalog
    from shadow_scout.harvest.classify import site_key

    async def main() -> list[str]:
        services = build_services(settings)
        try:
            await services.http.start()
            manual = ProviderDB(include_catalog=False).all(include_disabled=True)
            options = HarvestOptions(
                countries=countries or [], web_scan=web, check_blocklists=blocklists, force_dump=refresh,
                exclude_asns={a for p in manual for a in p.asns}, exclude_ids={p.id for p in manual},
                exclude_domains={d for p in manual if (d := site_key(p.website))},
                overrides=CatalogOverrides.load(),
            )
            if quiet:
                result = await harvest(services, options)
            else:
                with StepProgress("Сбор каталога…") as step:
                    result = await harvest(
                        services, options, log=step.update,
                        web_progress=lambda done, total: step.update(f"Проверка сайтов: {done}/{total}"),
                    )
        finally:
            await services.http.close()
        path = write_catalog(result.providers, out or (CATALOG_FILE if bundled else user_catalog_file()))
        by_country = Counter(p.hq_country for p in result.providers)
        lines = [f"Каталог: {len(result.providers)} провайдеров → {path}"]
        lines.append(f"Подтверждён VPS на сайте: {result.stats['vps_confirmed']}, не подтверждён: {result.stats['not_confirmed']}")
        lines.append("Страны: " + ", ".join(f"{cc} {n}" for cc, n in by_country.most_common(25)))
        dropped = ", ".join(f"{k.removeprefix('drop:')} {v}" for k, v in sorted(result.stats.items()) if k.startswith("drop:"))
        lines.append(f"Отсеяно: {dropped}")
        return lines

    return asyncio.run(main())


def save_last_result(result: SearchResult) -> None:
    try:
        last_result_file().write_text(result.model_dump_json(indent=None), encoding="utf-8")
    except OSError as exc:
        console.print(f"[warn]Не удалось сохранить последний отчёт: {exc}[/warn]")


def load_last_result() -> SearchResult | None:
    path = last_result_file()
    if not path.exists():
        return None
    try:
        return SearchResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        console.print(f"[warn]Не удалось прочитать последний отчёт: {exc}[/warn]")
        return None


def do_export(result: SearchResult, formats: list[str], directory: Path | None, settings: Settings, basename: str | None = None) -> list[Path]:
    directory = directory or Path(settings.general.export_dir).expanduser()
    return export_many(result, formats, directory, basename)


def select_providers(db: ProviderDB, query: SearchQuery) -> list[Provider]:
    return db.filter(query)


def plan_search(db: ProviderDB, query: SearchQuery) -> selection.Plan:
    """Фильтры базы → план кандидатов: лучшие на каждую локацию, а не первые по алфавиту."""
    return selection.plan_candidates(db.filter(query), query)


def report_to_result(report: RiskReport, title: str = "Проверка") -> SearchResult:
    return SearchResult(query=SearchQuery(), reports=[report], title=title)
