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
