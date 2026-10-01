"""Живое отображение прогресса поиска: общий прогресс, активные провайдеры, последние результаты."""

from __future__ import annotations

import time
from collections import OrderedDict

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from shadow_scout.analysis.engine import ProgressHooks
from shadow_scout.models import VERDICT_LABELS_RU, Provider, RiskReport
from shadow_scout.ui.theme import console, score_bar, verdict_style

STAGE_LABELS = {
    "asn": "ASN",
    "prefixes": "префиксы · списки",
    "cheburcheck": "cheburcheck",
    "ipapi": "тип IP",
    "probe": "TCP-пробы",
    "score": "оценка",
}


class SearchProgress:
    def __init__(self, total: int, title: str = "Анализ провайдеров") -> None:
        self.total = total
        self.title = title
        self.progress = Progress(
            SpinnerColumn(style="accent"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None, style="#2b3654", complete_style="#7c9cff", finished_style="#22c55e"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("[muted]осталось[/muted]"),
            TimeRemainingColumn(),
            expand=True,
        )
        self.task_id = self.progress.add_task(title, total=total)
        self.active: OrderedDict[str, tuple[Provider, str, float]] = OrderedDict()
        self.recent: list[RiskReport] = []
        self.logs: list[str] = []
        self.live: Live | None = None
        self.started = time.monotonic()

    # ───── hooks ─────
    def on_stage(self, provider: Provider, stage: str, message: str) -> None:
        self.active[provider.id] = (provider, stage, time.monotonic())
        self._refresh()

    def on_done(self, report: RiskReport) -> None:
        self.active.pop(report.provider.id, None)
        self.recent.insert(0, report)
        self.recent = self.recent[:8]
        self.progress.advance(self.task_id, 1)
        self._refresh()

    def on_log(self, message: str) -> None:
        self.logs.append(message)
        self.logs = self.logs[-5:]
        self._refresh()

    def hooks(self) -> ProgressHooks:
        return ProgressHooks(on_stage=self.on_stage, on_done=self.on_done, on_log=self.on_log)

    # ───── rendering ─────
    def _render(self) -> Group:
        active = Table(box=box.SIMPLE, show_header=False, pad_edge=False, expand=True)
        active.add_column(width=2)
        active.add_column(min_width=22)
        active.add_column(style="muted")
        for provider, stage, since in list(self.active.values())[:10]:
            active.add_row(Spinner("dots", style="accent"), provider.name, f"{STAGE_LABELS.get(stage, stage)} · {time.monotonic() - since:.0f} с")
        if not self.active:
            active.add_row("", Text("ожидание…", style="muted"), "")

        recent = Table(box=box.SIMPLE, show_header=False, pad_edge=False, expand=True)
        recent.add_column(min_width=22)
        recent.add_column(min_width=14)
        recent.add_column()
        for r in self.recent:
            recent.add_row(r.provider.name, score_bar(r.survivability, 8, r.verdict), Text(VERDICT_LABELS_RU.get(r.verdict, r.verdict), style=verdict_style(r.verdict)))
        if not self.recent:
            recent.add_row(Text("пока нет результатов", style="muted"), "", "")

        panels = Table.grid(expand=True, padding=(0, 1))
        panels.add_column(ratio=1)
        panels.add_column(ratio=1)
        panels.add_row(
            Panel(active, title="Сейчас анализируются", border_style="#243152", padding=(0, 1)),
            Panel(recent, title="Последние результаты", border_style="#243152", padding=(0, 1)),
        )
        items = [self.progress, panels]
        if self.logs:
            items.append(Text("\n".join(self.logs), style="muted"))
        return Group(*items)

    def _refresh(self) -> None:
        if self.live is not None:
            self.live.update(self._render())

    def __enter__(self) -> SearchProgress:
        self.live = Live(self._render(), console=console, refresh_per_second=8, transient=True)
        self.live.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self.live is not None:
            self.live.__exit__(*exc)
            self.live = None


class StepProgress:
    """Простой спиннер для подготовительных шагов (загрузка списков и т. п.)."""

    def __init__(self, title: str) -> None:
        self.progress = Progress(SpinnerColumn(style="accent"), TextColumn("[bold]{task.description}"), TimeElapsedColumn(), console=console, transient=True)
        self.task_id = self.progress.add_task(title, total=None)

    def update(self, message: str) -> None:
        self.progress.update(self.task_id, description=message)

    def __enter__(self) -> StepProgress:
        self.progress.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self.progress.__exit__(*exc)
