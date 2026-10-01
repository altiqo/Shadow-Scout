"""Правила классификации сетей PeeringDB: похожа ли организация на VPS/хостинг-провайдера.

Только чистые функции без сети — их проще проверять тестами и подкручивать правилами.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from shadow_scout.models import ProviderSize, registrable_domain

# Признаки хостинга в названии организации/сети/домена (en + локальные языки).
HOST_KEYWORDS = re.compile(
    r"host|vps|vds|cloud|server|srv|datacent|data[ _-]?cent|\bdc\b|\bcolo(cation)?\b|dedic|iaas|webspace|"
    r"tárhely|tarhely|h[eé]bergement|alojamiento|alojamento|webbhotell|veebimajutus|talpinim|serwer|sunucu|palvelin",
    re.I,
)

# «Сильные» признаки хостинга: слово «cloud» одно слишком общее (консалтинг, SaaS), «server» и «host» — почти всегда про серверы.
STRONG_HOST_KEYWORDS = re.compile(
    r"host|vps|vds|dedic|\bcolo(cation)?\b|datacent|data[ _-]?cent|server|"
    r"servidor|serveur|serwer|szerver|sunucu|palvelin|tárhely|tarhely|h[eé]bergement|alojamiento|alojamento|hospedagem|"
    r"webbhotell|veebimajutus|talpinim|stre[žz]nik|poslu[žz]itelj",
    re.I,
)

# Типы сетей PeeringDB, которые заведомо не про аренду серверов.
DENY_TYPES = {"Route Server", "Route Collector", "Educational/Research", "Government", "Non-Profit"}

# Организации, которые не продают VPS: точки обмена трафиком, операторы связи, CDN/антиDDoS, вузы, банки…
DENY_NAME = re.compile(
    r"\b(ix|ixp|exchange|route[ -]?servers?|peering|nren|univers\w*|school|college|akadem\w*|academy|institut\w*|"
    r"research|ministry|government|municipal\w*|police|hospital|bank|insurance|broadcast\w*|television|radio|"
    r"telecom\w*|telekom\w*|telefonica|mobile|wireless|broadband|cable|fiber|fibre|ddos|cdn|akamai|cloudflare|fastly|"
    r"stormwall|imperva|vodafone|orange|swisscom|telia|telenor|registry|registrar|vpn|"
    r"health|hospital|clinic|medical|pharma|association|city of|county|schools?|financial|logistics|mortgage|"
    r"church|diocese|library|museum|water|utilit\w*|energie|energy|power)\b",
    re.I,
)

# Гипермасштабные и CDN-провайдеры: в каталог не попадают (их место — в ручной базе).
BIG_BRANDS = re.compile(
    r"\b(amazon|aws|google|microsoft|azure|oracle|alibaba|tencent|cloudflare|akamai|fastly|digitalocean|linode|"
    r"vultr|ovh|hetzner|leaseweb|scaleway|contabo|ionos|1&1|rackspace|equinix|cogent|hurricane electric|"
    r"level ?3|lumen|telia|gcore|g-core|m247|choopa|quadranet|packet|zenlayer|datapacket|cdn77|bunny)\b",
    re.I,
)

# Российские бренды и признаки: такие провайдеры помечаются ru_ties и по умолчанию исключаются.
RU_BRANDS = re.compile(
    r"\b(aeza|pq[ -]?hosting|timeweb|selectel|ruvds|reg\.?ru|beget|firstvds|vdsina|4vps|serverspace|itldc|"
    r"hostzealot|netangels|sprinthost|masterhost|jino|nic\.ru|rusonyx|mchost|agava|hostkey|vsys|ihc|justhost|"
    r"fornex|vps\.house|hosting\.?ru|rucloud|cloud4y|ucloud|yandex|mail\.?ru|vk\.com|rostelecom|mts|beeline|"
    r"megafon|rtcomm|ttk|transtelecom|dataline|ixcellerate|ispserver|ihor|cloudmts)\b",
    re.I,
)
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".by", ".рф", ".kz")

LEGAL_SUFFIXES = re.compile(
    r"[\s,]+(d\.?\s?o\.?\s?o\.?|doo|s\.?r\.?o\.?|sro|gmbh(\s*&\s*co\.?\s*kg)?|ag|ltd\.?|limited|llc|l\.l\.c\.|inc\.?|oy|ab|as|"
    r"a/s|aps|uab|sia|o[uü]|kft\.?|zrt\.?|bv|b\.v\.|nv|n\.v\.|sa|s\.a\.|sas|sarl|srl|s\.r\.l\.|spa|s\.p\.a\.|"
    r"sp\.?\s?z\s?o\.?o\.?|ehf|hf|ood|eood|ad|e\.k\.|kg|ug|plc|lda|s\.l\.u?\.?|sl|slu|pty|pte|kk|co\.?|corp\.?|"
    r"corporation|s\.?c\.?|snc|s\.?a\.?s\.?|a\.?s\.?|bvba|cvba|vof|ek|eurl|ltda|eood|zao|ooo|oao)\.?$",
    re.I,
)

# Страны, организации из которых в каталог не берём (юрисдикции, где хостер обязан сотрудничать с РКН и аналогами).
HOSTILE_COUNTRIES = {"RU", "BY", "KZ", "KG", "UZ", "IR", "CN", "TM", "TJ", "KP", "SY", "CU"}


# Почтовые и служебные домены: по ним сайт провайдера не угадать.
GENERIC_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "mail.ru", "yandex.ru", "yandex.com", "ya.ru", "bk.ru", "inbox.ru", "list.ru",
    "gmx.com", "gmx.de", "gmx.net", "web.de", "t-online.de", "aol.com", "zoho.com", "ripe.net", "apnic.net",
    "arin.net", "lacnic.net", "afrinic.net", "abuse.net", "example.com",
}


def domain_from_email(email: str) -> str | None:
    """Домен из abuse-адреса, если он похож на домен самого провайдера."""
    domain = email.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    if "." not in domain or domain in GENERIC_MAIL_DOMAINS or domain.endswith(".ripe.net") or is_big_brand(domain):
        return None
    return domain


def has_host_keyword(*texts: str | None) -> bool:
    return any(HOST_KEYWORDS.search(t) for t in texts if t)


def has_strong_host_keyword(*texts: str | None) -> bool:
    return any(STRONG_HOST_KEYWORDS.search(t) for t in texts if t)


def site_key(website: str | None) -> str:
    """Регистрируемый домен сайта: staff.aruba.it → aruba.it (пусто, если сайта нет)."""
    return registrable_domain(website_domain(website)) or ""


def site_stem(website: str | None) -> str:
    """Значимая часть домена без поддоменов и зоны: cloud.orange-business.com → orange-business, host.co.uk → host."""
    return site_key(website).split(".", 1)[0]


def is_denied(name: str) -> bool:
    return bool(DENY_NAME.search(name))


def is_big_brand(*texts: str | None) -> bool:
    return any(BIG_BRANDS.search(t) for t in texts if t)


def website_domain(website: str | None) -> str | None:
    if not website:
        return None
    text = website.strip()
    if not text:
        return None
    host = text.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().lower()
    host = host.split("@")[-1].split(":", 1)[0]
    host = host.removeprefix("www.")
    return host if "." in host else None


def normalize_website(website: str | None) -> str | None:
    domain = website_domain(website)
    return f"https://{domain}" if domain else None


def ru_linked(name: str, website: str | None, org_country: str | None = None) -> bool:
    """Эвристика «связи с РФ»: российские бренды, ru-домены, кириллица в названии."""
    domain = website_domain(website) or ""
    if org_country and org_country.upper() in HOSTILE_COUNTRIES:
        return True
    if domain.endswith(RU_TLDS):
        return True
    if re.search(r"[а-яё]", name, re.I):
        return True
    return bool(RU_BRANDS.search(name) or RU_BRANDS.search(domain))


LEGAL_PREFIXES = re.compile(r"^(sia|uab|o[uü]|ooo|zao|oao|tov)\s+", re.I)


def clean_name(name: str) -> str:
    """Убирает юридические префиксы и суффиксы (SIA, d.o.o., GmbH, Ltd …) и лишние пробелы."""
    text = re.sub(r"\s+", " ", name).strip(" ,.-")
    text = LEGAL_PREFIXES.sub("", text).strip() or text
    for _ in range(3):  # «Foo Hosting Ltd.» → «Foo Hosting»; суффиксов может быть несколько
        stripped = LEGAL_SUFFIXES.sub("", text).strip(" ,.-")
        if stripped == text or not stripped:
            break
        text = stripped
    return text or name.strip()


def slugify(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name).strip("-")
    return slug or "provider"


def normalize_city(city: str | None) -> str | None:
    if not city:
        return None
    text = re.sub(r"\s*\(.*?\)", "", city).strip(" ,.-")
    text = re.sub(r"\s+", " ", text)
    if not text or len(text) > 40 or re.search(r"\d{3,}", text):
        return None
    if text.isupper() or text.islower():
        text = text.title()
    return text


def size_class(ipv4: int) -> ProviderSize:
    if ipv4 <= 4096:
        return "micro"
    if ipv4 <= 32768:
        return "small"
    if ipv4 <= 262144:
        return "medium"
    if ipv4 <= 1_048_576:
        return "large"
    return "hyperscale"


def popularity_for(size: ProviderSize) -> int:
    """Популярность в RU-сообществе по умолчанию: неизвестные локальные хостеры почти не засвечены."""
    return {"micro": 1, "small": 1, "medium": 2, "large": 3, "hyperscale": 4}[size]


def ip_type_for(pdb_types: list[str] | set[str]) -> str:
    types = set(pdb_types)
    if "Cable/DSL/ISP" in types and "Content" not in types:
        return "mixed"
    return "dch"


@dataclass
class OrgCandidate:
    """Организация из PeeringDB со всеми её сетями — кандидат в провайдеры."""

    org_id: int
    org_name: str
    country: str
    city: str | None
    website: str | None
    nets: list[dict] = field(default_factory=list)
    locations: list[tuple[str, str | None]] = field(default_factory=list)  # (страна, город); HQ первой
    origin: str = "peeringdb"  # peeringdb | asn-name (только имя ASN: сайт придётся искать, а хостинг — подтверждать)

    @property
    def pdb_types(self) -> list[str]:
        out: list[str] = []
        for n in self.nets:
            for t in n.get("info_types") or ([n["info_type"]] if n.get("info_type") else []):
                if t and t not in out:
                    out.append(t)
        return out

    @property
    def text(self) -> str:
        parts = [self.org_name]
        for n in self.nets:
            parts += [n.get("name") or "", n.get("aka") or ""]
        return " ".join(parts)

    @property
    def keyword(self) -> bool:
        # по домену — только его значимая часть: поддомен «cloud.» у большой компании не делает её хостером
        return has_host_keyword(self.text, site_stem(self.website))

    @property
    def strong_keyword(self) -> bool:
        return has_strong_host_keyword(self.text, site_stem(self.website))


_NAME_STOP = {
    "gmbh", "ltd", "llc", "inc", "oy", "ab", "sia", "uab", "kft", "sro", "doo", "ehf", "the", "hosting", "host", "internet", "cloud", "online",
    "net", "network", "networks", "services", "solutions", "group", "limited", "corp", "datacenter", "data", "center", "centre", "server", "servers",
    "web", "systems", "telecom", "technologies", "technology", "company", "business", "digital",
}


def name_tokens(text: str) -> set[str]:
    """Значимые слова названия (без юридических форм и общих слов вроде hosting/cloud) — для сверки названия с доменом."""
    return {t for t in re.split(r"[^a-z0-9]+", slugify(text).replace("-", " ")) if len(t) >= 3 and t not in _NAME_STOP}


def website_plausible(org_name: str, handle: str, website: str | None, title: str | None = None) -> bool:
    """Похож ли найденный сайт на название организации (домен или заголовок страницы содержат её значимое слово).

    Нужна для сетей, найденных только по имени ASN: там сайт угадывается по abuse-адресу и может принадлежать
    родительской компании или апстриму, а не самому провайдеру.
    """
    domain = website_domain(website)
    if not domain:
        return False
    stem = re.sub(r"[^a-z0-9]", "", site_stem(website))
    # название целиком («Datacenter d.o.o.» → datacenter) против домена: общие слова вроде datacenter тут и есть бренд
    whole = re.sub(r"[^a-z0-9]", "", slugify(clean_name(org_name)))
    if len(whole) >= 4 and len(stem) >= 4 and (whole in stem or stem in whole):
        return True
    words = name_tokens(org_name) | name_tokens(handle)
    if not words:
        return True  # название из одних общих слов («Hosting Ltd») — сверять не с чем
    title_words = name_tokens(title or "")
    return any(w in stem or (len(stem) >= 4 and stem in w) for w in words) or bool(words & title_words)


def pick_display_name(cand: OrgCandidate) -> str:
    """Название провайдера: имя сети PeeringDB (обычно это бренд), иначе организации."""
    options: list[str] = []
    if cand.origin == "peeringdb":
        for n in sorted(cand.nets, key=lambda n: -(n.get("info_prefixes4") or 0)):
            for key in ("name", "aka"):
                value = (n.get(key) or "").strip()
                if value:
                    options.append(value)
    options.append(cand.org_name)
    domain = website_domain(cand.website)
    stem = domain.split(".")[0] if domain else ""
    chosen = None
    for value in options:
        low = value.lower()
        if re.match(r"^as\s?-?\d+", low) or len(value) > 48 or "(as" in low:
            continue
        if stem and stem in re.sub(r"[^a-z0-9]", "", low):
            chosen = value
            break
        if chosen is None:
            chosen = value
    return clean_name(chosen or cand.org_name)


def candidate_decision(cand: OrgCandidate) -> str:
    """keep — подходит; deny — отбросить; maybe — оставить, если сайт подтвердит хостинг."""
    types = set(cand.pdb_types)
    if types and types <= DENY_TYPES:
        return "deny"
    if is_big_brand(cand.text, website_domain(cand.website)):
        return "deny"
    # «не хостер» по названию снимает только сильный признак (host/server/vps…): одно слово «cloud» — это и «St. Cloud»,
    # и консалтинг, и SaaS
    if is_denied(cand.org_name) and not cand.strong_keyword:
        return "deny"
    if cand.keyword:
        return "keep"
    if "Content" in types:
        return "maybe"
    return "deny"
