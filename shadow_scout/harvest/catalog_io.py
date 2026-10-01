"""Чтение и запись каталога провайдеров (JSON). Без тяжёлых зависимостей — его импортирует загрузчик базы."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shadow_scout import __version__
from shadow_scout.models import Provider
from shadow_scout.paths import DATA_DIR, data_dir

CATALOG_FILE = DATA_DIR / "providers_auto.json"  # поставляется с программой
CATALOG_VERSION = 1


def user_catalog_file() -> Path:
    """Каталог, собранный командой harvest на машине пользователя (перекрывает поставляемый)."""
    return data_dir() / "providers.catalog.json"


def write_catalog(providers: list[Provider], path: Path | None = None, sources: list[str] | None = None) -> Path:
    """Сохраняет каталог: заголовок + по одному провайдеру на строку (удобно для diff в git)."""
    path = path or CATALOG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    header = {
        "version": CATALOG_VERSION,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "tool": f"shadow-scout {__version__}",
        "sources": sources or ["PeeringDB", "ipverse/asn-ip", "RIPEstat", "сайты провайдеров"],
        "count": len(providers),
    }
    lines = [
        json.dumps(p.model_dump(mode="json", exclude_defaults=True, exclude={"source"}), ensure_ascii=False, separators=(",", ":"))
        for p in providers
    ]
    head = ",\n".join(f'"{k}": {json.dumps(v, ensure_ascii=False)}' for k, v in header.items())
    path.write_text("{\n" + head + ',\n"providers": [\n' + ",\n".join(lines) + "\n]\n}\n", encoding="utf-8", newline="\n")  # LF на любой ОС: файл поставляется с пакетом
    return path


def read_catalog(path: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(заголовок, записи провайдеров); пустой результат, если файла нет или он повреждён."""
    path = path or CATALOG_FILE
    if not path.exists():
        return {}, []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, []
    items = raw.get("providers") if isinstance(raw, dict) else raw
    meta = {k: v for k, v in raw.items() if k != "providers"} if isinstance(raw, dict) else {}
    return meta, [i for i in (items or []) if isinstance(i, dict)]
