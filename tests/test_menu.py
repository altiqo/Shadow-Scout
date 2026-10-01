"""Интерактивное меню, управляемое скриптом ответов (без TTY)."""

from __future__ import annotations

from collections import deque

import pytest

from shadow_scout.ui import menu as menu_mod


class Script:
    """Подменяет menu.ask: отдаёт заранее заданные ответы по очереди."""

    def __init__(self, answers: list[object]) -> None:
        self.answers = deque(answers)
        self.asked: list[str] = []

    def __call__(self, prompt):
        text = getattr(prompt, "_question_text", None) or str(getattr(prompt, "application", "")) or repr(prompt)
        self.asked.append(text)
        if not self.answers:
            raise AssertionError(f"скрипт ответов исчерпан на вопросе: {text}")
        return self.answers.popleft()


@pytest.fixture
def scripted(monkeypatch, patched_services, tmp_path):
    monkeypatch.setattr(menu_mod, "pause", lambda: None)
    monkeypatch.setattr(menu_mod, "open_path", lambda path: None)
    monkeypatch.setattr(menu_mod.console, "clear", lambda: None)
    monkeypatch.setattr(menu_mod, "user_providers_file", lambda: tmp_path / "providers.user.yaml")
    import shadow_scout.providers as providers_mod

    monkeypatch.setattr(providers_mod, "user_providers_file", lambda: tmp_path / "providers.user.yaml")

    def install(answers: list[object]) -> Script:
        script = Script(answers)
        monkeypatch.setattr(menu_mod, "ask", script)
        return script

    return install


def test_search_wizard_runs_and_exports(scripted, settings, tmp_path):
    settings.general.export_dir = str(tmp_path / "exports")
    script = scripted([
        ["SE"],                 # страны
        ["no_ru", "no_large"],  # требования
        "",                     # цена
        "any",                  # тип IP
        0,                      # размер ASN без ограничения
        "any",                  # риск
        "6",                    # лимит
        True,                   # запустить
        "export",               # действие в результатах
        ["html", "md"],         # форматы
        str(tmp_path / "exports"),
        False,                  # не открывать
        "detail",               # подробности
        0,                      # первый провайдер
        "back",
    ])
    app = menu_mod.MenuApp(settings)
    app.do_search()
    assert app.last_result is not None and app.last_result.reports
    files = sorted((tmp_path / "exports").glob("*"))
    assert {f.suffix for f in files} == {".html", ".md"}
    assert not script.answers


def test_search_wizard_no_matches(scripted, settings):
    scripted([["IS"], ["trial", "hourly"], "1", "isp", 16384, "low", "5"])
    app = menu_mod.MenuApp(settings)
    app.do_search()  # нет кандидатов → сообщение, без исключений
    assert app.last_result is None


def test_check_target_from_menu(scripted, settings):
    scripted(["target", False, "AS24940", False])
    app = menu_mod.MenuApp(settings)
    app.do_check()
    assert app.last_result and app.last_result.reports[0].provider.asns == [24940]


def test_check_provider_from_db(scripted, settings):
    scripted(["db", False, "GleSYS", False])
    app = menu_mod.MenuApp(settings)
    app.do_check()
    assert app.last_result and app.last_result.reports[0].provider.id == "glesys"


def test_discovery_add_to_db(scripted, settings, tmp_path):
    scripted(["Швеция (SE)", "5", False, 1 << 32, "add", [0]])
    app = menu_mod.MenuApp(settings)
    app.do_discover()
    assert app.db.user and app.db.user[0].source == "user"
    assert (tmp_path / "providers.user.yaml").exists()


def test_discovery_analyze(scripted, settings):
    scripted(["Швеция (SE)", "5", False, 1 << 32, "analyze", [0, 1], "back"])
    app = menu_mod.MenuApp(settings)
    app.do_discover()
    assert app.last_result and len(app.last_result.reports) == 2


def test_db_toggle_and_add(scripted, settings, tmp_path):
    scripted([
        "toggle", "glesys",
        "add", "My Host", "my-host", "https://my.example", "", "My Host", "fi", "FI/Helsinki, SE", "micro", "1", "isp", True, True, "4", False, "note",
        "list", "back",
    ])
    app = menu_mod.MenuApp(settings)
    app.do_db()
    assert "glesys" in app.db.disabled_ids
    added = app.db.get("my-host")
    assert added and added.hq_country == "FI" and [loc.country for loc in added.locations] == ["FI", "SE"]


def test_settings_roundtrip(scripted, settings, monkeypatch):
    saved = {"n": 0}
    monkeypatch.setattr(type(settings), "save", lambda self: saved.__setitem__("n", saved["n"] + 1))
    scripted(["network", "socks5://127.0.0.1:1080", "15", "1", "3", True, "scoring", "weights"] + [str(v) for v in settings.scoring.weights.model_dump().values()] + ["back"])
    app = menu_mod.MenuApp(settings)
    app.do_settings()
    assert settings.network.proxy == "socks5://127.0.0.1:1080"
    assert settings.network.concurrency == 3
    assert saved["n"] >= 2


def test_update_and_export_last(scripted, settings, monkeypatch, tmp_path):
    scripted(["export", ["json"], str(tmp_path / "x"), False, "back"])
    app = menu_mod.MenuApp(settings)
    app.do_update()
    from shadow_scout.models import SearchQuery, SearchResult

    app.last_result = SearchResult(query=SearchQuery(), reports=[], title="пусто")
    app.do_export()
    assert (tmp_path / "x").exists()
