"""CLI через typer CliRunner с подменой сборки сервисов на мок-транспорт."""

from __future__ import annotations

from typer.testing import CliRunner

from shadow_scout import cli
from shadow_scout.cli import app


def test_cli_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0 and "Shadow Scout" in result.output


def test_cli_search_and_export(patched_services, tmp_path):
    runner_ = CliRunner()
    result = runner_.invoke(app, ["search", "-c", "SE", "--hourly", "--limit", "10", "--quiet", "--export", "html,csv", "--out", str(tmp_path / "r")])
    assert result.exit_code == 0, result.output
    files = sorted((tmp_path / "r").glob("*"))
    assert {f.suffix for f in files} == {".html", ".csv"}
    html = next(f for f in files if f.suffix == ".html").read_text(encoding="utf-8")
    assert "GleSYS" in html and "AS42708" in html


def test_cli_check_asn(patched_services):
    result = CliRunner().invoke(app, ["check", "AS24940", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "HETZNER" in result.output.upper()
    assert "Критический" in result.output or "Высокий" in result.output


def test_cli_check_provider_id(patched_services):
    result = CliRunner().invoke(app, ["check", "glesys", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "GleSYS" in result.output


def test_cli_discover(patched_services):
    result = CliRunner().invoke(app, ["discover", "SE", "--no-keywords", "--max", "5", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "AS99999" in result.output


def test_cli_export_without_result(patched_services):
    result = CliRunner().invoke(app, ["export"])
    assert result.exit_code == 1


def test_cli_update(patched_services):
    result = CliRunner().invoke(app, ["update"])
    assert result.exit_code == 0, result.output
    assert "Re:filter" in result.output
    _ = cli


def test_cli_search_prints_best_per_location(patched_services, tmp_path):
    result = CliRunner().invoke(app, ["search", "-c", "SE", "-c", "FI", "-c", "IS", "-k", "2", "--limit", "60", "--quiet", "--export", "md,csv", "--out", str(tmp_path / "r")])
    assert result.exit_code == 0, result.output
    for label in ("Швеция (SE)", "Финляндия (FI)", "Исландия (IS)"):
        assert label in result.output  # на каждую запрошенную локацию — свой блок
    md = (next((tmp_path / "r").glob("*.md"))).read_text(encoding="utf-8")
    assert "## Лучшие по локациям" in md and "### Швеция (SE)" in md
    csv_text = next((tmp_path / "r").glob("*.csv")).read_text(encoding="utf-8-sig")
    assert "Лучший в локациях" in csv_text.splitlines()[0]


def test_cli_search_by_city_and_strict_flags(patched_services):
    result = CliRunner().invoke(app, ["search", "-c", "SE", "--by-city", "--hourly", "--strict", "-k", "3", "--limit", "30", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "Stockholm" in result.output  # группировка по городам


def test_cli_search_quick_only_skips_cheburcheck(patched_services, fake_api):
    result = CliRunner().invoke(app, ["search", "-c", "SE", "--deep", "0", "--limit", "25", "--quiet"])
    assert result.exit_code == 0, result.output
    assert not [c for c in fake_api.calls if "cheburcheck.ru/api/v1/check" in c]
    assert "◐" in result.output  # значок «быстрая проверка»


def test_cli_providers_stats_and_source_filter(patched_services):
    stats = CliRunner().invoke(app, ["providers", "--stats"])
    assert stats.exit_code == 0 and "Швеция" in stats.output and "Каталог" in stats.output
    curated = CliRunner().invoke(app, ["providers", "-c", "SE", "--source", "curated"])
    assert curated.exit_code == 0 and "GleSYS" in curated.output and "[авто]" not in curated.output
    assert CliRunner().invoke(app, ["providers", "--source", "bogus"]).exit_code != 0


def test_cli_harvest_writes_loadable_catalog(patched_services, tmp_path):
    from shadow_scout.harvest.catalog_io import read_catalog

    out = tmp_path / "catalog.json"
    result = CliRunner().invoke(app, ["harvest", "--no-web", "-c", "SE", "-c", "HR", "--out", str(out), "--quiet"])
    assert result.exit_code == 0, result.output
    meta, items = read_catalog(out)
    names = {i["name"] for i in items}
    assert meta["count"] == len(items) and {"Nordic VPS", "Hosty Balkans"} <= names
    assert "Каталог:" in result.output


def test_cli_paths_lists_catalog_locations(patched_services):
    result = CliRunner().invoke(app, ["paths"])
    assert result.exit_code == 0
    assert "каталог:" in result.output and "providers.catalog.json" in result.output and "providers_auto.json" in result.output
