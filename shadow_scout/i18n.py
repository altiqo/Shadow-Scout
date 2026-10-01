"""Минимальная локализация интерфейса (ru — основной, en — запасной)."""

from __future__ import annotations

_LANG = "ru"

STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        "menu.search": "Поиск VPS-провайдеров (мастер)",
        "menu.check": "Проверить провайдера / ASN / IP / домен",
        "menu.discover": "Обнаружение малых ASN по стране",
        "menu.db": "База провайдеров",
        "menu.update": "Обновить списки блокировок",
        "menu.export": "Экспорт последнего отчёта",
        "menu.settings": "Настройки",
        "menu.about": "О программе",
        "menu.exit": "Выход",
        "verdict.low": "Низкий риск",
        "verdict.moderate": "Умеренный риск",
        "verdict.high": "Высокий риск",
        "verdict.critical": "Критический риск",
        "verdict.unknown": "Нет данных",
        "col.provider": "Провайдер",
        "col.country": "Страны",
        "col.asn": "ASN",
        "col.size": "IPv4",
        "col.blocked": "Блок.",
        "col.type": "Тип IP",
        "col.trial": "Trial",
        "col.hourly": "Почас.",
        "col.price": "от €",
        "col.score": "Выжив.",
        "col.verdict": "Вердикт",
        "col.conf": "Увер.",
    },
    "en": {
        "menu.search": "Search VPS providers (wizard)",
        "menu.check": "Check a provider / ASN / IP / domain",
        "menu.discover": "Discover small ASNs by country",
        "menu.db": "Provider database",
        "menu.update": "Update blocklists",
        "menu.export": "Export last report",
        "menu.settings": "Settings",
        "menu.about": "About",
        "menu.exit": "Exit",
        "verdict.low": "Low risk",
        "verdict.moderate": "Moderate risk",
        "verdict.high": "High risk",
        "verdict.critical": "Critical risk",
        "verdict.unknown": "No data",
        "col.provider": "Provider",
        "col.country": "Countries",
        "col.asn": "ASN",
        "col.size": "IPv4",
        "col.blocked": "Blocked",
        "col.type": "IP type",
        "col.trial": "Trial",
        "col.hourly": "Hourly",
        "col.price": "from €",
        "col.score": "Surviv.",
        "col.verdict": "Verdict",
        "col.conf": "Conf.",
    },
}


def set_language(lang: str) -> None:
    global _LANG
    _LANG = lang if lang in STRINGS else "ru"


def get_language() -> str:
    return _LANG


def t(key: str, **kwargs: object) -> str:
    table = STRINGS.get(_LANG, STRINGS["ru"])
    text = table.get(key) or STRINGS["ru"].get(key) or key
    return text.format(**kwargs) if kwargs else text
