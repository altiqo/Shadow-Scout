"""Проверка сайта провайдера: продаёт ли VPS, есть ли почасовая оплата. Анализ текста — чистая функция."""

from __future__ import annotations

import asyncio
import html as html_lib
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from shadow_scout.cache import DiskCache
from shadow_scout.harvest.classify import normalize_website, website_domain

# Явные признаки продажи VPS / облачных серверов (en + локальные языки).
VPS_RE = re.compile(
    r"\bvps\b|\bvds\b|\bvserver\b|virtual private server|virtual server|virtuelle[rn]? server|cloud ?servers?|cloud ?vps|"
    r"managed vps|kvm ?(vps|server|cloud)|serveurs? (virtuels?|cloud|vps)|servidor(es)? (virtual(es)?|cloud|vps)|"
    r"server(i)? virtual[ei]|virtu[aá]ln[ií]? server|virtu[aá]lny server|virtu[aá]lis szerver|wirtualny serwer|"
    r"serwery? (vps|wirtualn\w+)|virtuaal(ne)? ?server|virtuali[ųu]? serveri|virtu[āa]lais serveris|virtuell server|"
    r"virtuaalipalvelin|virtuele server|molnserver|virtu[aá]lny|виртуальн\w+ сервер|облачн\w+ сервер"
)
# Признаки хостинга вообще: веб-хостинг, выделенные серверы, колокация.
HOSTING_RE = re.compile(
    r"hosting|hébergement|hebergement|alojamiento|alojamento|webbhotell|tárhely|tarhely|veebimajutus|talpinim|"
    r"dedicated servers?|dedikovan\w+ server|dedizierte[rn]? server|colocation|co-location|serverhousing|server housing|"
    r"rack ?space|datacent(er|re)|data cent(er|re)|выделенн\w+ сервер|хостинг"
)
# Почасовая тарификация: только фразы про оплату/биллинг. Голые «hourly», «stündlich», «tunnis», «óradíj» дают массу
# ложных срабатываний («hourly backups», «half an hour», «tunnistautuminen» — финское «аутентификация», «külön óradíj» за поддержку).
HOURLY_RE = re.compile(
    r"per hour|by the hour|/ ?hour\b|/ ?hr\b|hourly(?! (?:backups?|snapshots?|checks?|monitoring|updates?|reports?|scans?))|"
    r"pro stunde|stundenweise|stundengenau|stundenabrechnung|abrechnung (?:pro|nach) stunde|"
    r"per uur\b|per-uur|uurlijks (?:afgerekend|gefactureerd)|"
    r"[àa] l'heure\b|par heure|facturation (?:horaire|à l'heure)|"
    r"por hora|facturaci[óo]n por horas|"
    r"all'ora\b|per ora\b|fatturazione oraria|"
    r"[óo]r[áa]nk[ée]nti? (?:elsz[aá]mol|sz[aá]ml|fizet)|[óo]rad[ií]jas|"
    r"za hodinu\b|hodinov\w+ (?:platba|fakturace|účtování|fakturácia)|"
    r"za godzin[ęe]\b|rozliczenie godzinowe|p[łl]atno[śs][ćc] godzinowa|"
    r"per timme|timdebitering|"
    r"tuntilaskutus|tuntiveloitus|tuntiperusteinen|tunneittain|"
    r"tunnip[õo]hine|tunni kaupa|"
    r"stundas tarifs|valandinis (?:tarifas|apmokėjimas)|"
    r"почасов\w+|оплата за час|руб/?час|₽/?час|за час использования"
)
SUBPAGE_RE = re.compile(
    r"vps|vds|cloud|server|virtual|dedic|hosting|compute|iaas|price|pricing|plans|preise|prix|precio|prezzi|[áa]rak|ceny|cennik|cenik|tarif",
    re.I,
)
_TAG_BLOCKS = re.compile(r"<(script|style|noscript|svg|template)\b.*?</\1>", re.I | re.S)
_COMMENTS = re.compile(r"<!--.*?-->", re.S)
_TAGS = re.compile(r"<[^>]+>")
_LINK = re.compile(r"<a\s[^>]*?href=[\"']([^\"'#]+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
_LANG = re.compile(r"<html[^>]*\blang=[\"']([a-zA-Z-]+)", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_CYRILLIC = re.compile(r"[а-яёіїєґ]", re.I)
_RUSSIAN_ONLY = re.compile(r"[ыэё]", re.I)  # этих букв нет в болгарском, сербском, украинском и македонском

MAX_TEXT = 300_000
FAIL_TTL_SECONDS = 2 * 86400
SCAN_VERSION = 3  # увеличивайте при изменении правил распознавания: кеш старых результатов станет недействительным


@dataclass
class WebScan:
    url: str = ""
    fetched: bool = False
    final_url: str | None = None
    vps: bool = False
    hosting: bool = False
    hourly: bool = False
    hourly_evidence: str = ""  # фрагмент страницы с упоминанием почасовой оплаты — чтобы человек мог проверить
    cyrillic: bool = False  # кириллица (в т. ч. болгарский, украинский…)
    russian: bool = False  # именно русский язык
    lang: str | None = None
    title: str | None = None
    pages: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> WebScan:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class PageAnalysis:
    vps: bool = False
    hosting: bool = False
    hourly: bool = False
    hourly_evidence: str = ""
    cyrillic: bool = False
    russian: bool = False
    lang: str | None = None
    title: str | None = None
    links: list[str] = field(default_factory=list)


def visible_text(markup: str) -> str:
    text = _COMMENTS.sub(" ", markup)
    text = _TAG_BLOCKS.sub(" ", text)
    text = _TAGS.sub(" ", text)
    text = html_lib.unescape(text)
    return re.sub(r"\s+", " ", text).strip().lower()[:MAX_TEXT]


def analyze_html(markup: str, base_url: str = "") -> PageAnalysis:
    """Признаки VPS/хостинга/почасовой оплаты в тексте страницы + ссылки на подстраницы с тарифами."""
    text = visible_text(markup)
    result = PageAnalysis()
    result.vps = bool(VPS_RE.search(text))
    result.hosting = result.vps or bool(HOSTING_RE.search(text))
    hourly = HOURLY_RE.search(text)
    result.hourly = bool(hourly)
    if hourly:
        result.hourly_evidence = text[max(0, hourly.start() - 70) : hourly.end() + 70].strip()
    sample = text[:20000]
    letters = sum(1 for ch in sample if ch.isalpha())
    result.cyrillic = bool(letters) and len(_CYRILLIC.findall(sample)) / letters > 0.2
    result.russian = result.cyrillic and len(_RUSSIAN_ONLY.findall(sample)) / max(1, letters) > 0.008
    lang = _LANG.search(markup[:4000])
    result.lang = lang.group(1).lower() if lang else None
    title = _TITLE.search(markup[:20000])
    if title:
        result.title = re.sub(r"\s+", " ", html_lib.unescape(_TAGS.sub("", title.group(1)))).strip()[:120] or None
    if base_url:
        base_host = urlparse(base_url).netloc.lower().removeprefix("www.")
        seen: dict[str, int] = {}
        for href, label in _LINK.findall(markup[:400_000]):
            label_text = re.sub(r"\s+", " ", _TAGS.sub("", label)).strip().lower()
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(base_url, href.strip())
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https") or parsed.netloc.lower().removeprefix("www.") != base_host:
                continue
            path = parsed.path.rstrip("/") or "/"
            if path == "/" or re.search(r"\.(jpg|jpeg|png|gif|svg|pdf|css|js|zip)$", path, re.I):
                continue
            score = 0
            if SUBPAGE_RE.search(path) or SUBPAGE_RE.search(label_text):
                score = 2 if re.search(r"vps|vds|cloud|virtual", path + " " + label_text) else 1
            if score:
                clean = parsed._replace(query="", fragment="").geturl()
                seen[clean] = max(seen.get(clean, 0), score)
        result.links = [u for u, _ in sorted(seen.items(), key=lambda kv: (-kv[1], len(kv[0])))][:6]
    return result


async def _fetch(client: httpx.AsyncClient, url: str, max_bytes: int = 1_500_000) -> tuple[str, str] | None:
    try:
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                return None
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            body = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            return str(response.url), body.decode(encoding, errors="replace")
    except (httpx.HTTPError, ValueError, OSError):
        return None


async def scan_site(client: httpx.AsyncClient, website: str, max_pages: int = 4) -> WebScan:
    base = normalize_website(website)
    scan = WebScan(url=website or "")
    if not base:
        scan.error = "нет сайта"
        return scan
    domain = website_domain(website) or ""
    page = await _fetch(client, base + "/")
    if page is None:
        page = await _fetch(client, f"http://{domain}/")
    if page is None:
        scan.error = "сайт недоступен"
        return scan
    final_url, markup = page
    scan.fetched = True
    scan.final_url = final_url
    first = analyze_html(markup, final_url)
    scan.vps, scan.hosting, scan.hourly, scan.cyrillic, scan.lang, scan.title = (
        first.vps, first.hosting, first.hourly, first.cyrillic, first.lang, first.title,
    )
    scan.hourly_evidence = first.hourly_evidence
    scan.russian = first.russian
    scan.pages = 1
    for link in first.links:
        if scan.pages >= max_pages or (scan.vps and scan.hourly):
            break
        sub = await _fetch(client, link)
        if sub is None:
            continue
        scan.pages += 1
        analysis = analyze_html(sub[1])
        scan.vps = scan.vps or analysis.vps
        scan.hosting = scan.hosting or analysis.hosting
        if analysis.hourly and not scan.hourly:
            scan.hourly_evidence = analysis.hourly_evidence
        scan.hourly = scan.hourly or analysis.hourly
    return scan


async def scan_many(
    sites: dict[str, str],
    *,
    concurrency: int = 24,
    proxy: str | None = None,
    user_agent: str = "ShadowScout/1.0",
    cache: DiskCache | None = None,
    ttl_seconds: float = 14 * 86400,
    progress: Callable[[int, int], None] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, WebScan]:
    """Сканирует сайты параллельно; ключ — произвольный идентификатор организации."""
    results: dict[str, WebScan] = {}
    kwargs: dict = {
        "timeout": httpx.Timeout(12.0, connect=6.0),
        "headers": {"User-Agent": user_agent, "Accept": "text/html,*/*;q=0.5", "Accept-Language": "en,*;q=0.5"},
        "follow_redirects": True,
        "verify": False,  # читаем только публичные страницы; у мелких хостеров нередко битые сертификаты
        "limits": httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency),
    }
    if transport is not None:
        kwargs["transport"] = transport
    elif proxy:
        kwargs["proxy"] = proxy
    semaphore = asyncio.Semaphore(max(1, concurrency))
    done = 0

    async with httpx.AsyncClient(**kwargs) as client:

        async def worker(key: str, site: str) -> None:
            nonlocal done
            cache_key = f"webscan:v{SCAN_VERSION}:{website_domain(site) or site}"
            cached = (cache.get(cache_key, ttl_seconds) or cache.get(cache_key + ":fail", FAIL_TTL_SECONDS)) if cache else None
            if cached is not None:
                results[key] = WebScan.from_dict(cached)
            else:
                async with semaphore:
                    try:
                        scan = await asyncio.wait_for(scan_site(client, site), timeout=60)
                    except Exception as exc:  # noqa: BLE001 — один сайт не должен ронять сбор
                        scan = WebScan(url=site, error=f"ошибка проверки: {type(exc).__name__}")
                results[key] = scan
                if cache:
                    # удачные результаты живут долго, неудачи — недолго (сайт мог лежать временно), но повторно не мучаем
                    cache.set(cache_key if (scan.fetched or scan.error == "нет сайта") else cache_key + ":fail", scan.to_dict())
            done += 1
            if progress:
                progress(done, len(sites))

        await asyncio.gather(*(worker(k, s) for k, s in sites.items()))
    return results
