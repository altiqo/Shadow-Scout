"""Тема оформления: консоль rich, стили, баннер, стиль questionary."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

from shadow_scout import __version__

THEME = Theme(
    {
        "title": "bold #7c9cff",
        "accent": "#7c9cff",
        "muted": "#8d9bbd",
        "ok": "bold #22c55e",
        "warn": "bold #eab308",
        "bad": "bold #ef4444",
        "info": "#38bdf8",
        "verdict.low": "bold #22c55e",
        "verdict.moderate": "bold #eab308",
        "verdict.high": "bold #f97316",
        "verdict.critical": "bold #ef4444",
        "verdict.unknown": "bold #94a3b8",
        "sev.low": "#22c55e",
        "sev.moderate": "#eab308",
        "sev.high": "#f97316",
        "sev.critical": "#ef4444",
        "sev.unknown": "#94a3b8",
        "menu.key": "bold #7c9cff",
    }
)

console = Console(theme=THEME, highlight=False)

VERDICT_ICON = {"low": "●", "moderate": "●", "high": "●", "critical": "●", "unknown": "○"}

BANNER_LINES = [
    "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗",
    "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝",
    "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    ███████╗██║     ██║   ██║██║   ██║   ██║   ",
    "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ╚════██║██║     ██║   ██║██║   ██║   ██║   ",
    "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   ",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝     ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   ",
]

GRADIENT = ["#a5b4fc", "#8ea2ff", "#7c9cff", "#6b8cff", "#5b7cf5", "#4c6fe8"]


def banner() -> Text:
    text = Text()
    width = console.size.width
    if width < 100:
        text.append("  SHADOW SCOUT\n", style="bold #7c9cff")
    else:
        for line, color in zip(BANNER_LINES, GRADIENT, strict=True):
            text.append(line + "\n", style=color)
    text.append(f"  v{__version__} · поиск VPS под VPN вне радара РКН", style="muted")
    return text


def verdict_style(verdict: str) -> str:
    return f"verdict.{verdict}" if verdict in ("low", "moderate", "high", "critical") else "verdict.unknown"


def score_bar(value: float, width: int = 10, verdict: str = "unknown") -> Text:
    filled = int(round(value / 100 * width))
    bar = Text()
    bar.append("█" * filled, style=f"sev.{verdict if verdict != 'unknown' else 'unknown'}")
    bar.append("░" * (width - filled), style="#2b3654")
    bar.append(f" {value:3.0f}", style=verdict_style(verdict))
    return bar


def questionary_style():
    from questionary import Style

    return Style(
        [
            ("qmark", "fg:#7c9cff bold"),
            ("question", "bold"),
            ("answer", "fg:#22c55e bold"),
            ("pointer", "fg:#7c9cff bold"),
            ("highlighted", "fg:#7c9cff bold"),
            ("selected", "fg:#22c55e"),
            ("separator", "fg:#8d9bbd"),
            ("instruction", "fg:#8d9bbd"),
            ("text", ""),
            ("disabled", "fg:#6b7280 italic"),
        ]
    )
