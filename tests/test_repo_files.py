"""Служебные файлы репозитория: CI-воркфлоу, YAML-данные, документация. Ошибка в них не ловится ни одним другим тестом."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflows_are_valid_yaml_with_expected_jobs():
    """GitHub отклоняет воркфлоу целиком из-за одной синтаксической ошибки (например, двоеточия в названии шага)."""
    files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert files, "нет файлов воркфлоу"
    for path in files:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict) and workflow.get("jobs"), path.name
        triggers = workflow.get("on") or workflow.get(True)  # в YAML 1.1 ключ «on» превращается в True
        assert triggers, path.name
        for name, job in workflow["jobs"].items():
            assert job.get("steps"), (path.name, name)
            assert all("run" in step or "uses" in step for step in job["steps"]), (path.name, name)


@pytest.mark.parametrize("name", ["providers.yaml", "countries.yaml", "catalog_overrides.yaml"])
def test_shipped_yaml_data_files_parse(name):
    data = yaml.safe_load((ROOT / "shadow_scout" / "data" / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict) and data


def test_pyproject_packages_the_data_files():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "data/*.json" in text and "data/*.yaml" in text  # без этого каталог не попал бы в установленный пакет


@pytest.mark.parametrize("name", ["README.md", "CHANGELOG.md"])
def test_docs_have_no_unfilled_placeholders(name):
    assert "{{" not in (ROOT / name).read_text(encoding="utf-8"), name


def test_version_is_consistent():
    import re

    import shadow_scout

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^version = "{re.escape(shadow_scout.__version__)}"', pyproject, re.M)
    assert f"## {shadow_scout.__version__}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
