"""Файловые пути приложения (конфиг, кеш, пользовательские данные, отчёты)."""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir, user_data_dir

from shadow_scout import APP_SLUG

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
FONTS_DIR = DATA_DIR / "fonts"


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else None


def config_dir() -> Path:
    path = _env_path("SHADOW_SCOUT_CONFIG_DIR") or Path(user_config_dir(APP_SLUG))
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_dir() -> Path:
    path = _env_path("SHADOW_SCOUT_CACHE_DIR") or Path(user_cache_dir(APP_SLUG))
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_dir() -> Path:
    path = _env_path("SHADOW_SCOUT_DATA_DIR") or Path(user_data_dir(APP_SLUG))
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_file() -> Path:
    return config_dir() / "config.yaml"


def user_providers_file() -> Path:
    return data_dir() / "providers.user.yaml"


def last_result_file() -> Path:
    return data_dir() / "last_result.json"


def default_reports_dir() -> Path:
    return Path.home() / "ShadowScout" / "reports"
