"""Экспорт результатов в файлы: HTML, PDF, XLSX, CSV, JSON, Markdown."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from shadow_scout.models import SearchResult

FORMATS: dict[str, str] = {
    "html": "HTML-отчёт (таблица + подробности, открывается в браузере)",
    "pdf": "PDF-отчёт (печатная версия)",
    "xlsx": "Excel-таблица",
    "csv": "CSV-таблица",
    "md": "Markdown",
    "json": "JSON (полные данные для скриптов)",
}


def export(result: SearchResult, fmt: str, directory: Path, basename: str | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    basename = basename or f"shadow-scout_{datetime.now().strftime('%Y-%m-%d_%H-%M')}"
    path = directory / f"{basename}.{fmt}"
    if fmt == "html":
        from shadow_scout.export.html import write_html

        write_html(result, path)
    elif fmt == "pdf":
        from shadow_scout.export.pdf import write_pdf

        write_pdf(result, path)
    elif fmt == "xlsx":
        from shadow_scout.export.table import write_xlsx

        write_xlsx(result, path)
    elif fmt == "csv":
        from shadow_scout.export.table import write_csv

        write_csv(result, path)
    elif fmt == "md":
        from shadow_scout.export.table import write_markdown

        write_markdown(result, path)
    elif fmt == "json":
        from shadow_scout.export.table import write_json

        write_json(result, path)
    else:
        raise ValueError(f"Неизвестный формат: {fmt}")
    return path


def export_many(result: SearchResult, formats: list[str], directory: Path, basename: str | None = None) -> list[Path]:
    basename = basename or f"shadow-scout_{datetime.now().strftime('%Y-%m-%d_%H-%M')}"
    return [export(result, fmt, directory, basename) for fmt in formats]
