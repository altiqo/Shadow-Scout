"""Интерактивное меню (questionary + rich): мастер поиска, проверка, discovery, база, настройки."""

from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from pathlib import Path

import questionary
from questionary import Choice, Separator
from rich.panel import Panel
from rich.text import Text

from shadow_scout import __version__
from shadow_scout.analysis.discovery import Candidate, DiscoveryOptions, parse_keywords
from shadow_scout.config import DEFAULT_BLOCKLISTS, BlocklistSource, Settings
from shadow_scout.export import FORMATS
from shadow_scout.i18n import set_language, t
from shadow_scout.models import Location, Provider, SearchQuery, SearchResult
from shadow_scout.paths import cache_dir, config_file, user_providers_file
from shadow_scout.providers import ProviderDB, load_countries
from shadow_scout.runner import (
    do_export,
    load_last_result,
    run_check,
    run_discovery,
    run_search,
    update_lists,
)
from shadow_scout.ui import views
from shadow_scout.ui.theme import banner, console, questionary_style

QS = questionary_style()


class Exit(Exception):
    pass


def ask(prompt):
    answer = prompt.ask()
    if answer is None:
        raise Exit()
    return answer


def pause() -> None:
    try:
        questionary.press_any_key_to_continue("Нажмите любую клавишу, чтобы продолжить…", style=QS).ask()
    except (KeyboardInterrupt, EOFError):
        pass


def open_path(path: Path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            if path.suffix.lower() in (".html", ".htm"):
                webbrowser.open(path.as_uri())
            else:
                subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[warn]Не удалось открыть {path}: {exc}[/warn]")


class MenuApp:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = ProviderDB()
        self.countries = load_countries()
        self.last_result: SearchResult | None = None
        set_language(settings.general.language)

    # ───────────────────────── main loop ─────────────────────────
    def run(self) -> None:
        try:
            while True:
                self.show_header()
                choice = ask(
                    questionary.select(
                        "Что делаем?",
                        choices=[
                            Choice("🔍  " + t("menu.search"), "search"),
                            Choice("🎯  " + t("menu.check"), "check"),
                            Choice("🧭  " + t("menu.discover"), "discover"),
                            Choice("📚  " + t("menu.db"), "db"),
                            Choice("🔄  " + t("menu.update"), "update"),
                            Choice("📤  " + t("menu.export"), "export"),
                            Choice("⚙️   " + t("menu.settings"), "settings"),
                            Choice("ℹ️   " + t("menu.about"), "about"),
                            Choice("⏻   " + t("menu.exit"), "exit"),
                        ],
                        style=QS,
                        use_shortcuts=True,
                    )
                )
                if choice == "exit":
                    break
                try:
                    getattr(self, f"do_{choice}")()
                except Exit:
                    continue
                except KeyboardInterrupt:
                    console.print("[muted]Прервано.[/muted]")
        except (Exit, KeyboardInterrupt, EOFError):
            pass
        console.print("[muted]До встречи. Проверяйте выданный IP перед оплатой.[/muted]")

    def show_header(self) -> None:
        console.clear()
        if self.settings.general.show_banner:
            console.print(banner())
        status = Text()
        from shadow_scout.net.blocklists import BlocklistManager
        from shadow_scout.net.http import HealthRegistry, HttpClient

        mgr = BlocklistManager(self.settings, HttpClient(self.settings.network, HealthRegistry()))
        ages = [mgr.cache.age_seconds(b.url) for b in self.settings.sources.blocklists if b.enabled]
        loaded = [a for a in ages if a is not None]
        if not loaded:
            status.append("  списки блокировок не загружены — выберите «Обновить списки» или они подгрузятся при первом поиске", style="warn")
        else:
            hours = max(loaded) / 3600
            style = "ok" if hours <= self.settings.cache.blocklists_ttl_hours else "warn"
            status.append(f"  списки блокировок: {len(loaded)}/{len(ages)} загружены, самому старому {hours:.1f} ч", style=style)
        status.append(f"   ·   провайдеров в базе: {len(self.db.all())}", style="muted")
        status.append(f"   ·   конфиг: {config_file()}", style="muted")
        console.print(status)
        console.print()

    # ───────────────────────── search wizard ─────────────────────────
    def ask_countries(self, preselect_low: bool = True) -> list[str]:
        choices: list = [Choice("— Все страны (без фильтра) —", "ALL")]
        low = set(self.countries.low_radar_codes())
        for region, items in self.countries.by_region().items():
            choices.append(Separator(f"── {region} ──"))
            for c in items:
                label = f"{c.name_ru} ({c.code})" + ("  ★ низкий радар" if c.radar == "low" else ("  ⚠ " + c.radar if c.radar in ("elevated", "hostile") else ""))
                choices.append(Choice(label, c.code, checked=preselect_low and c.code in low))
        picked = ask(questionary.checkbox("Страны/локации (пробел — выбрать, Enter — подтвердить):", choices=choices, style=QS, validate=lambda v: True))
        if "ALL" in picked:
            return []
        return [c for c in picked if c != "ALL"]

    def do_search(self) -> None:
        console.rule("[title]Мастер поиска VPS-провайдеров[/title]")
        countries = self.ask_countries()
        opts = ask(
            questionary.checkbox(
                "Требования:",
                choices=[
                    Choice("Нужен бесплатный trial", "trial"),
                    Choice("Нужна почасовая оплата", "hourly"),
                    Choice("Исключить провайдеров со связями с РФ", "no_ru", checked=True),
                    Choice("Исключить крупные/гипермасштабные хостинги", "no_large", checked=True),
                    Choice("Выполнить живые TCP-пробы с этой машины (полезно из РФ)", "live", checked=self.settings.live_probe.enabled),
                ],
                style=QS,
            )
        )
        price_raw = ask(questionary.text("Максимальная цена, €/мес (пусто — без ограничения):", style=QS, validate=lambda v: v.strip() == "" or _is_float(v) or "введите число"))
        ip_pref = ask(
            questionary.select(
                "Предпочтение по типу IP-пула:",
                choices=[Choice("Любой", "any"), Choice("ISP / смешанный (резидентные и бизнес-пулы)", "isp"), Choice("Только датацентровые (DCH)", "dch")],
                style=QS,
            )
        )
        max_asn = ask(
            questionary.select(
                "Максимальный размер сети (IPv4-адресов в ASN):",
                choices=[
                    Choice("≤ 16 384 (/18) — маленькие сети", 16384),
                    Choice("≤ 65 536 (/16)", 65536),
                    Choice("≤ 262 144 (/14)", 262144),
                    Choice("Без ограничения", 0),
                ],
                default=self.settings.scoring.thresholds.max_asn_ipv4_default,
                style=QS,
            )
        )
        max_risk = ask(
            questionary.select(
                "Показывать провайдеров с риском не выше:",
                choices=[Choice("Любой (показать всех)", "any"), Choice("Умеренный", "moderate"), Choice("Низкий", "low")],
                style=QS,
            )
        )
        limit_raw = ask(questionary.text("Сколько провайдеров анализировать (максимум):", default=str(self.settings.general.results_limit), style=QS, validate=lambda v: v.strip().isdigit() or "введите целое число"))

        query = SearchQuery(
            countries=countries,
            require_trial="trial" in opts,
            require_hourly="hourly" in opts,
            max_price_eur=float(price_raw.replace(",", ".")) if price_raw.strip() else None,
            ip_type=["isp", "mixed"] if ip_pref == "isp" else (["dch"] if ip_pref == "dch" else []),
            max_asn_ipv4=max_asn or None,
            max_size="medium" if "no_large" in opts else None,
            max_risk=None if max_risk == "any" else max_risk,
            include_ru_ties="no_ru" not in opts,
            live_probe="live" in opts,
            limit=int(limit_raw),
        )
        providers = self.db.filter(query)
        if not providers:
            console.print(Panel("[warn]Под эти фильтры не подходит ни один провайдер из базы. Ослабьте условия или добавьте провайдеров в базу / через discovery.[/warn]", border_style="yellow"))
            pause()
            return
        providers = sorted(providers, key=lambda p: (p.popularity_ru, {"micro": 0, "small": 1, "medium": 2, "large": 3, "hyperscale": 4}[p.size], p.name))[: query.limit]
        console.print(f"[muted]Запрос:[/muted] {query.describe()}")
        console.print(f"[muted]Кандидатов из базы:[/muted] [bold]{len(providers)}[/bold] — " + ", ".join(p.name for p in providers[:12]) + (" …" if len(providers) > 12 else ""))
        if not ask(questionary.confirm("Запустить анализ?", default=True, style=QS)):
            return
        result = run_search(self.settings, providers, query, title="Поиск VPS: " + (", ".join(countries) if countries else "все страны"))
        if query.max_asn_ipv4:
            kept = [r for r in result.reports if not r.total_ipv4 or r.total_ipv4 <= query.max_asn_ipv4]
            dropped = len(result.reports) - len(kept)
            result.reports = kept
            if dropped:
                console.print(f"[muted]Скрыто {dropped} провайдеров с сетью больше заданного размера.[/muted]")
        self.last_result = result
        self.show_result(result)

    # ───────────────────────── results ─────────────────────────
    def show_result(self, result: SearchResult) -> None:
        while True:
            console.clear()
            console.rule(f"[title]{result.title}[/title]")
            console.print(views.summary_line(result))
            console.print(views.results_table(result))
            console.print(views.sources_panel(result.sources))
            reports = result.sorted_reports()
            choices = [Choice("📤  Экспортировать отчёт (HTML / PDF / XLSX / …)", "export")]
            if reports:
                choices.append(Choice("🔎  Подробный отчёт по провайдеру", "detail"))
            choices.append(Choice("↩   Назад в меню", "back"))
            action = ask(questionary.select("Действие:", choices=choices, style=QS))
            if action == "back":
                return
            if action == "export":
                self.export_dialog(result)
            elif action == "detail":
                pick = ask(
                    questionary.select(
                        "Провайдер:",
                        choices=[Choice(f"{i}. {r.provider.name} — {r.survivability:.0f}/100", i - 1) for i, r in enumerate(reports, start=1)] + [Choice("↩ назад", -1)],
                        style=QS,
                    )
                )
                if pick >= 0:
                    console.clear()
                    console.print(views.report_panel(reports[pick]))
                    pause()

    def export_dialog(self, result: SearchResult) -> None:
        formats = ask(
            questionary.checkbox(
                "Форматы экспорта:",
                choices=[Choice(f"{fmt.upper():5} — {desc}", fmt, checked=fmt in self.settings.general.default_exports) for fmt, desc in FORMATS.items()],
                style=QS,
            )
        )
        if not formats:
            return
        directory = ask(questionary.text("Папка для сохранения:", default=self.settings.general.export_dir, style=QS))
        paths = do_export(result, formats, Path(directory).expanduser(), self.settings)
        for p in paths:
            console.print(f"[ok]✔[/ok] {p}")
        if ask(questionary.confirm("Открыть первый файл?", default=True, style=QS)):
            open_path(paths[0])
        pause()

    # ───────────────────────── check ─────────────────────────
    def do_check(self) -> None:
        console.rule("[title]Проверка провайдера / ASN / IP / домена[/title]")
        mode = ask(
            questionary.select(
                "Что проверяем?",
                choices=[Choice("Провайдера из базы", "db"), Choice("Произвольную цель: ASN (AS42708), IP или домен", "target"), Choice("↩ назад", "back")],
                style=QS,
            )
        )
        if mode == "back":
            return
        live = ask(questionary.confirm("Выполнить живые TCP-пробы с этой машины?", default=self.settings.live_probe.enabled, style=QS))
        if mode == "db":
            providers = self.db.all(include_disabled=True)
            name = ask(questionary.autocomplete("Название провайдера:", choices=[p.name for p in providers], style=QS, ignore_case=True, match_middle=True))
            provider = next((p for p in providers if p.name.lower() == name.lower()), None)
            if provider is None:
                console.print("[warn]Провайдер не найден[/warn]")
                pause()
                return
            result = run_check(self.settings, provider=provider, live=live)
        else:
            target = ask(questionary.text("Цель (AS12345 / 1.2.3.4 / example.com):", style=QS, validate=lambda v: bool(v.strip()) or "введите цель"))
            result = run_check(self.settings, target=target, live=live)
        self.last_result = result
        console.clear()
        console.print(views.report_panel(result.reports[0]))
        console.print(views.sources_panel(result.sources))
        if ask(questionary.confirm("Экспортировать отчёт?", default=False, style=QS)):
            self.export_dialog(result)

    # ───────────────────────── discovery ─────────────────────────
    def do_discover(self) -> None:
        console.rule("[title]Обнаружение малых ASN по стране[/title]")
        console.print(Panel(
            "Берём все маршрутизируемые ASN страны (RIPEstat / таблица ASN), фильтруем по ключевым словам (хостинг, облако, ISP…),\n"
            "затем для каждого кандидата считаем размер сети, пересечение со списками блокировок и тип по PeeringDB.\n"
            "Лучшие кандидаты можно добавить в базу и прогнать через полный анализ.",
            border_style="#243152",
        ))
        codes = sorted(self.countries.countries.values(), key=lambda c: c.name_ru)
        name = ask(questionary.autocomplete("Страна:", choices=[c.label() for c in codes], style=QS, ignore_case=True, match_middle=True))
        country = next((c.code for c in codes if c.label().lower() == name.lower()), name.strip().upper()[:2])
        max_c = ask(questionary.text("Сколько ASN анализировать (после фильтра):", default="60", style=QS, validate=lambda v: v.strip().isdigit() or "число"))
        use_kw = ask(questionary.confirm("Фильтровать по ключевым словам в названии?", default=True, style=QS))
        options = DiscoveryOptions(country=country, max_candidates=int(max_c), keyword_filter=use_kw)
        if use_kw:
            extra = ask(questionary.text("Дополнительные ключевые слова через запятую (пусто — стандартный набор):", default="", style=QS))
            if extra.strip():
                options.include_keywords = list(dict.fromkeys(options.include_keywords + parse_keywords(extra)))
        max_ipv4 = ask(questionary.select("Максимальный размер сети:", choices=[Choice("≤ 16 384", 16384), Choice("≤ 65 536", 65536), Choice("≤ 262 144", 262144), Choice("Без ограничения", 1 << 32)], default=262144, style=QS))
        options.max_ipv4 = max_ipv4
        candidates = run_discovery(self.settings, options)
        if not candidates:
            console.print("[warn]Кандидаты не найдены (проверьте доступ к RIPEstat/GitHub или ослабьте фильтр).[/warn]")
            pause()
            return
        console.clear()
        console.rule(f"[title]Discovery: {self.countries.name(country)} — {len(candidates)} кандидатов[/title]")
        console.print(views.discovery_table(candidates))
        action = ask(questionary.select("Действие:", choices=[Choice("Полный анализ выбранных кандидатов", "analyze"), Choice("Добавить выбранных в базу провайдеров", "add"), Choice("↩ назад", "back")], style=QS))
        if action == "back":
            return
        picked = ask(questionary.checkbox("Выберите кандидатов:", choices=[Choice(f"AS{c.asn} {c.name} — {c.ipv4_count} IPv4, в списках {c.blocked_share:.1%}", i, checked=i < 10) for i, c in enumerate(candidates[:40])], style=QS))
        chosen: list[Candidate] = [candidates[i] for i in picked]
        if not chosen:
            return
        if action == "add":
            for c in chosen:
                self.db.add_user(c.to_provider())
            console.print(f"[ok]Добавлено {len(chosen)} провайдеров в {user_providers_file()}[/ok]")
            pause()
            return
        providers = [c.to_provider() for c in chosen]
        query = SearchQuery(countries=[country], include_ru_ties=True)
        result = run_search(self.settings, providers, query, title=f"Discovery {self.countries.name(country)}")
        self.last_result = result
        self.show_result(result)

    # ───────────────────────── database ─────────────────────────
    def do_db(self) -> None:
        while True:
            console.clear()
            console.rule("[title]База провайдеров[/title]")
            action = ask(
                questionary.select(
                    "Действие:",
                    choices=[
                        Choice("Показать всех", "list"),
                        Choice("Фильтр по стране", "country"),
                        Choice("Добавить провайдера", "add"),
                        Choice("Включить / отключить провайдера", "toggle"),
                        Choice("Удалить пользовательского провайдера", "remove"),
                        Choice(f"Открыть файл пользовательской базы ({user_providers_file()})", "open"),
                        Choice("↩ назад", "back"),
                    ],
                    style=QS,
                )
            )
            if action == "back":
                return
            if action == "list":
                console.print(views.providers_table(self.db, self.db.all(include_disabled=True)))
                pause()
            elif action == "country":
                codes = self.ask_countries(preselect_low=False)
                providers = [p for p in self.db.all(include_disabled=True) if not codes or set(codes) & set(p.countries)]
                console.print(views.providers_table(self.db, providers))
                pause()
            elif action == "add":
                self.add_provider_form()
            elif action == "toggle":
                providers = self.db.all(include_disabled=True)
                pid = ask(questionary.autocomplete("id провайдера:", choices=[p.id for p in providers], style=QS, ignore_case=True, match_middle=True))
                if self.db.get(pid):
                    disabled = pid in self.db.disabled_ids
                    self.db.set_disabled(pid, not disabled)
                    console.print(f"[ok]{pid}: {'включён' if disabled else 'отключён'}[/ok]")
                else:
                    console.print("[warn]Не найден[/warn]")
                pause()
            elif action == "remove":
                if not self.db.user:
                    console.print("[muted]Пользовательских провайдеров нет[/muted]")
                else:
                    pid = ask(questionary.select("Удалить:", choices=[Choice(f"{p.id} — {p.name}", p.id) for p in self.db.user] + [Choice("↩ отмена", "")], style=QS))
                    if pid and self.db.remove_user(pid):
                        console.print(f"[ok]Удалён {pid}[/ok]")
                pause()
            elif action == "open":
                if not user_providers_file().exists():
                    self.db.save_user()
                open_path(user_providers_file())
                pause()

    def add_provider_form(self) -> None:
        console.print("[muted]Заполните карточку провайдера. Пустые поля — значения по умолчанию.[/muted]")
        name = ask(questionary.text("Название:", style=QS, validate=lambda v: bool(v.strip()) or "обязательно"))
        pid = ask(questionary.text("id (латиницей, без пробелов):", default="".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-"), style=QS))
        website = ask(questionary.text("Сайт (https://…):", default="", style=QS))
        asns_raw = ask(questionary.text("ASN через запятую (пусто — искать по названию):", default="", style=QS))
        asn_search = ask(questionary.text("Строка поиска ASN (если ASN не указан):", default=name, style=QS)) if not asns_raw.strip() else None
        hq = ask(questionary.text("Страна HQ (ISO-код, напр. SE):", default="", style=QS, validate=lambda v: len(v.strip()) == 2 or "два символа"))
        locs_raw = ask(questionary.text("Локации: код[/город] через запятую (напр. SE/Stockholm, FI):", default=hq.upper(), style=QS))
        size = ask(questionary.select("Размер компании:", choices=["micro", "small", "medium", "large", "hyperscale"], default="small", style=QS))
        pop = ask(questionary.select("Популярность у RU-аудитории (1 — неизвестен, 5 — массово):", choices=["1", "2", "3", "4", "5"], default="1", style=QS))
        ip_type = ask(questionary.select("Тип IP-пула:", choices=["dch", "isp", "mixed", "unknown"], default="dch", style=QS))
        trial = ask(questionary.confirm("Есть бесплатный trial?", default=False, style=QS))
        hourly = ask(questionary.confirm("Есть почасовая оплата?", default=False, style=QS))
        price = ask(questionary.text("Минимальная цена, €/мес (пусто — неизвестно):", default="", style=QS, validate=lambda v: v.strip() == "" or _is_float(v) or "число"))
        ru_ties = ask(questionary.confirm("Есть связи с РФ (владельцы/юрлицо/офис)?", default=False, style=QS))
        notes = ask(questionary.text("Примечание:", default="", style=QS))
        locations = []
        for item in locs_raw.split(","):
            item = item.strip()
            if not item:
                continue
            cc, _, city = item.partition("/")
            locations.append(Location(country=cc.strip(), city=city.strip() or None))
        provider = Provider(
            id=pid, name=name, website=website.strip() or None,
            asns=[int(a) for a in asns_raw.replace("AS", "").replace("as", "").split(",") if a.strip().isdigit()],
            asn_search=asn_search, hq_country=hq, locations=locations, size=size, popularity_ru=int(pop), ip_type=ip_type,
            trial=trial, hourly=hourly, min_price_eur=float(price.replace(",", ".")) if price.strip() else None, ru_ties=ru_ties, notes=notes, tags=["user"],
        )
        self.db.add_user(provider)
        console.print(f"[ok]Сохранено в {user_providers_file()}[/ok]")
        pause()

    # ───────────────────────── update / export ─────────────────────────
    def do_update(self) -> None:
        console.rule("[title]Обновление списков блокировок[/title]")
        for line in update_lists(self.settings):
            console.print("  " + line)
        pause()

    def do_export(self) -> None:
        result = self.last_result or load_last_result()
        if result is None:
            console.print("[warn]Отчётов ещё нет — сначала выполните поиск или проверку.[/warn]")
            pause()
            return
        self.last_result = result
        self.show_result(result)

    # ───────────────────────── settings ─────────────────────────
    def do_settings(self) -> None:
        while True:
            console.clear()
            console.rule("[title]Настройки[/title]")
            console.print(views.settings_overview(self.settings))
            section = ask(
                questionary.select(
                    "Раздел:",
                    choices=[
                        Choice("Общие (язык, папка экспорта, форматы, лимит)", "general"),
                        Choice("Сеть (прокси, таймауты, параллельность)", "network"),
                        Choice("Источники данных (cheburcheck, RIPEstat, PeeringDB, ip-api, списки)", "sources"),
                        Choice("Скоринг (веса сигналов, пороги вердиктов)", "scoring"),
                        Choice("Живые TCP-пробы", "live"),
                        Choice("Кеш (TTL, очистка)", "cache"),
                        Choice("Сбросить все настройки по умолчанию", "reset"),
                        Choice("↩ назад", "back"),
                    ],
                    style=QS,
                )
            )
            if section == "back":
                self.settings.save()
                return
            getattr(self, f"settings_{section}")()
            self.settings.save()

    def settings_general(self) -> None:
        g = self.settings.general
        g.language = ask(questionary.select("Язык интерфейса:", choices=[Choice("Русский", "ru"), Choice("English (частично)", "en")], default=g.language, style=QS))
        set_language(g.language)
        g.export_dir = ask(questionary.text("Папка экспорта:", default=g.export_dir, style=QS))
        g.default_exports = ask(questionary.checkbox("Форматы экспорта по умолчанию:", choices=[Choice(f, f, checked=f in g.default_exports) for f in FORMATS], style=QS))
        g.results_limit = int(ask(questionary.text("Лимит провайдеров в поиске:", default=str(g.results_limit), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        g.show_banner = ask(questionary.confirm("Показывать баннер?", default=g.show_banner, style=QS))

    def settings_network(self) -> None:
        n = self.settings.network
        proxy = ask(questionary.text("Прокси (http://user:pass@host:port или socks5://host:port; пусто — без прокси):", default=n.proxy or "", style=QS))
        n.proxy = proxy.strip() or None
        n.timeout_seconds = float(ask(questionary.text("Таймаут запроса, с:", default=str(n.timeout_seconds), style=QS, validate=_is_float)))
        n.retries = int(ask(questionary.text("Повторов при ошибке:", default=str(n.retries), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        n.concurrency = int(ask(questionary.text("Параллельных провайдеров:", default=str(n.concurrency), style=QS, validate=lambda v: v.strip().isdigit() and int(v) > 0 or "число > 0")))
        n.verify_tls = ask(questionary.confirm("Проверять TLS-сертификаты?", default=n.verify_tls, style=QS))

    def settings_sources(self) -> None:
        s = self.settings.sources
        which = ask(questionary.select("Источник:", choices=[Choice("cheburcheck.ru", "cc"), Choice("RIPEstat", "ripe"), Choice("PeeringDB", "pdb"), Choice("ip-api.com", "ipapi"), Choice("Списки блокировок", "lists"), Choice("↩ назад", "back")], style=QS))
        if which == "cc":
            s.cheburcheck.enabled = ask(questionary.confirm("Использовать cheburcheck?", default=s.cheburcheck.enabled, style=QS))
            s.cheburcheck.base_url = ask(questionary.text("Базовый URL (можно свой self-hosted инстанс):", default=s.cheburcheck.base_url, style=QS))
            s.cheburcheck.requests_per_minute = int(ask(questionary.text("Запросов в минуту (сервер лимитирует ~30):", default=str(s.cheburcheck.requests_per_minute), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
            s.cheburcheck.check_asn = ask(questionary.confirm("Проверять ASN?", default=s.cheburcheck.check_asn, style=QS))
            s.cheburcheck.check_website = ask(questionary.confirm("Проверять сайт провайдера?", default=s.cheburcheck.check_website, style=QS))
        elif which == "ripe":
            s.ripestat.enabled = ask(questionary.confirm("Использовать RIPEstat?", default=s.ripestat.enabled, style=QS))
            s.ripestat.requests_per_minute = int(ask(questionary.text("Запросов в минуту:", default=str(s.ripestat.requests_per_minute), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        elif which == "pdb":
            s.peeringdb.enabled = ask(questionary.confirm("Использовать PeeringDB?", default=s.peeringdb.enabled, style=QS))
            key = ask(questionary.text("API-ключ PeeringDB (необязательно, повышает лимиты):", default=s.peeringdb.api_key or "", style=QS))
            s.peeringdb.api_key = key.strip() or None
        elif which == "ipapi":
            s.ipapi.enabled = ask(questionary.confirm("Использовать ip-api.com (классификация hosting/ISP)?", default=s.ipapi.enabled, style=QS))
            s.ipapi.samples_per_asn = int(ask(questionary.text("Выборка адресов на ASN:", default=str(s.ipapi.samples_per_asn), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        elif which == "lists":
            self.settings_blocklists()

    def settings_blocklists(self) -> None:
        while True:
            s = self.settings.sources
            choices = [Choice(f"{'●' if b.enabled else '○'} {b.name} — {b.url}", i) for i, b in enumerate(s.blocklists)]
            choices += [Choice("+ Добавить свой список (CIDR по строкам)", "add"), Choice("Вернуть стандартный набор", "reset"), Choice("↩ назад", "back")]
            pick = ask(questionary.select("Списки блокировок:", choices=choices, style=QS))
            if pick == "back":
                return
            if pick == "reset":
                s.blocklists = list(DEFAULT_BLOCKLISTS)
                continue
            if pick == "add":
                name = ask(questionary.text("Название:", style=QS))
                url = ask(questionary.text("URL:", style=QS))
                if name.strip() and url.strip():
                    s.blocklists.append(BlocklistSource(name=name.strip(), url=url.strip()))
                continue
            b = s.blocklists[pick]
            act = ask(questionary.select(b.name, choices=[Choice("Включить/выключить", "toggle"), Choice("Изменить URL", "url"), Choice("Удалить", "del"), Choice("↩", "back")], style=QS))
            if act == "toggle":
                b.enabled = not b.enabled
            elif act == "url":
                b.url = ask(questionary.text("URL:", default=b.url, style=QS))
            elif act == "del":
                s.blocklists.pop(pick)

    def settings_scoring(self) -> None:
        sc = self.settings.scoring
        what = ask(questionary.select("Что настроить:", choices=[Choice("Веса сигналов", "weights"), Choice("Пороги вердиктов", "thresholds"), Choice("Сбросить скоринг по умолчанию", "reset"), Choice("↩ назад", "back")], style=QS))
        if what == "weights":
            for key, value in sc.weights.model_dump().items():
                new = ask(questionary.text(f"Вес «{key}» (0 — отключить сигнал):", default=str(value), style=QS, validate=_is_float))
                setattr(sc.weights, key, float(new.replace(",", ".")))
        elif what == "thresholds":
            th = sc.thresholds
            th.low_max = float(ask(questionary.text("Низкий риск: до", default=str(th.low_max), style=QS, validate=_is_float)))
            th.moderate_max = float(ask(questionary.text("Умеренный: до", default=str(th.moderate_max), style=QS, validate=_is_float)))
            th.high_max = float(ask(questionary.text("Высокий: до (далее — критический)", default=str(th.high_max), style=QS, validate=_is_float)))
            th.hard_blocked_share = float(ask(questionary.text("Доля заблокированных адресов для «критично» (0..1):", default=str(th.hard_blocked_share), style=QS, validate=_is_float)))
            th.small_asn_ipv4 = int(ask(questionary.text("«Маленькая» сеть, IPv4 ≤", default=str(th.small_asn_ipv4), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        elif what == "reset":
            self.settings.reset_section("scoring")

    def settings_live(self) -> None:
        lp = self.settings.live_probe
        lp.enabled = ask(questionary.confirm("Включать живые TCP-пробы по умолчанию?", default=lp.enabled, style=QS))
        ports = ask(questionary.text("Порты через запятую:", default=",".join(map(str, lp.ports)), style=QS))
        lp.ports = [int(p) for p in ports.split(",") if p.strip().isdigit()] or [443]
        lp.timeout_seconds = float(ask(questionary.text("Таймаут пробы, с:", default=str(lp.timeout_seconds), style=QS, validate=_is_float)))
        lp.samples_per_asn = int(ask(questionary.text("Адресов на ASN:", default=str(lp.samples_per_asn), style=QS, validate=lambda v: v.strip().isdigit() or "число")))
        lp.control_host = ask(questionary.text("Контрольный хост (должен быть доступен):", default=lp.control_host, style=QS))

    def settings_cache(self) -> None:
        c = self.settings.cache
        act = ask(questionary.select("Кеш:", choices=[Choice("Изменить TTL", "ttl"), Choice(f"Очистить кеш ({cache_dir()})", "clear"), Choice("↩ назад", "back")], style=QS))
        if act == "ttl":
            for key, value in c.model_dump().items():
                setattr(c, key, int(ask(questionary.text(f"{key}:", default=str(value), style=QS, validate=lambda v: v.strip().isdigit() or "число"))))
        elif act == "clear":
            import shutil

            root = cache_dir()
            removed = 0
            for child in root.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                    removed += 1
            console.print(f"[ok]Кеш очищен ({removed} разделов)[/ok]")
            pause()

    def settings_reset(self) -> None:
        if ask(questionary.confirm("Сбросить ВСЕ настройки?", default=False, style=QS)):
            self.settings = Settings()
            self.settings.save()
            console.print("[ok]Настройки сброшены[/ok]")
            pause()

    # ───────────────────────── about ─────────────────────────
    def do_about(self) -> None:
        console.clear()
        console.print(banner())
        console.print(Panel(
            f"[bold]Shadow Scout v{__version__}[/bold]\n\n"
            "Инструмент подбирает небольшие VPS-провайдеры под VPN и оценивает вероятность того, что их сети попали или попадут под блокировки РКН.\n\n"
            "[bold]Сигналы:[/bold] пересечение префиксов ASN со списками блокировок (antifilter, Re:filter), проверка ASN и сайта через cheburcheck.ru, "
            "размер сети и фрагментация (RIPEstat / ipverse), тип сети (PeeringDB, ip-api), популярность и масштаб, юрисдикция, "
            "CDN-диапазоны, связи с РФ / реестр хостеров РКН, жалобы пользователей, живые TCP-пробы.\n\n"
            "[bold]Источники:[/bold] cheburcheck.ru (LowderPlay/cheburcheck), antifilter.download, antifilter.network, 1andrevich/Re-filter-lists, "
            "123jjck/cdn-ip-ranges, RIPEstat Data API, PeeringDB, ip-api.com, ipverse/asn-info, ipverse/asn-ip.\n\n"
            "[muted]Оценка вероятностная. Чистый IP не защищает от DPI-блокировок протоколов — используйте маскирующиеся протоколы и проверяйте выданный IP перед оплатой.[/muted]\n\n"
            f"Конфиг: {config_file()}\nКеш: {cache_dir()}\nПользовательская база: {user_providers_file()}",
            title="О программе", border_style="#243152",
        ))
        pause()


def _is_float(value: str) -> bool | str:
    try:
        float(value.replace(",", "."))
        return True
    except ValueError:
        return "введите число"


def run_menu(settings: Settings) -> None:
    MenuApp(settings).run()
