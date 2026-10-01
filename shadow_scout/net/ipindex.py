"""Индекс IP-диапазонов: быстрый поиск вхождения и подсчёт пересечений (чистый Python)."""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections.abc import Iterable


def _parse_network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        addr = ipaddress.ip_address(text)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}")
    except ValueError:
        return None


class IntervalIndex:
    """Множество непересекающихся интервалов [start, end] над целыми числами."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._raw: list[tuple[int, int]] = []
        self._dirty = False

    def add(self, start: int, end: int) -> None:
        self._raw.append((start, end))
        self._dirty = True

    def add_network(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        self.add(int(net.network_address), int(net.broadcast_address))

    def _build(self) -> None:
        if not self._dirty:
            return
        merged: list[tuple[int, int]] = []
        for start, end in sorted(self._raw):
            if merged and start <= merged[-1][1] + 1:
                if end > merged[-1][1]:
                    merged[-1] = (merged[-1][0], end)
            else:
                merged.append((start, end))
        self._starts = [s for s, _ in merged]
        self._ends = [e for _, e in merged]
        self._dirty = False

    def __len__(self) -> int:
        self._build()
        return len(self._starts)

    def address_count(self) -> int:
        self._build()
        return sum(e - s + 1 for s, e in zip(self._starts, self._ends, strict=True))

    def contains(self, value: int) -> bool:
        self._build()
        idx = bisect_right(self._starts, value) - 1
        return idx >= 0 and self._ends[idx] >= value

    def overlap(self, start: int, end: int) -> int:
        """Сколько адресов из [start, end] покрыто индексом."""
        self._build()
        if not self._starts:
            return 0
        idx = bisect_right(self._starts, start) - 1
        if idx < 0:
            idx = 0
        total = 0
        while idx < len(self._starts) and self._starts[idx] <= end:
            s, e = self._starts[idx], self._ends[idx]
            lo, hi = max(s, start), min(e, end)
            if hi >= lo:
                total += hi - lo + 1
            idx += 1
        return total

    def overlapping_ranges(self, start: int, end: int, limit: int = 50) -> list[tuple[int, int]]:
        self._build()
        if not self._starts:
            return []
        idx = max(0, bisect_right(self._starts, start) - 1)
        out: list[tuple[int, int]] = []
        while idx < len(self._starts) and self._starts[idx] <= end:
            s, e = self._starts[idx], self._ends[idx]
            if min(e, end) >= max(s, start):
                out.append((max(s, start), min(e, end)))
                if len(out) >= limit:
                    break
            idx += 1
        return out


class NetworkSet:
    """Пара индексов (IPv4 + IPv6) с удобными методами над CIDR-строками."""

    def __init__(self) -> None:
        self.v4 = IntervalIndex()
        self.v6 = IntervalIndex()
        self.entries = 0

    def add_cidr(self, text: str) -> bool:
        net = _parse_network(text)
        if net is None:
            return False
        (self.v4 if net.version == 4 else self.v6).add_network(net)
        self.entries += 1
        return True

    def add_many(self, lines: Iterable[str]) -> int:
        count = 0
        for line in lines:
            if self.add_cidr(line):
                count += 1
        return count

    def contains_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        index = self.v4 if addr.version == 4 else self.v6
        return index.contains(int(addr))

    def overlap_cidr(self, cidr: str) -> tuple[int, int]:
        """(адресов заблокировано, адресов всего) для префикса."""
        net = _parse_network(cidr)
        if net is None:
            return 0, 0
        index = self.v4 if net.version == 4 else self.v6
        start, end = int(net.network_address), int(net.broadcast_address)
        return index.overlap(start, end), end - start + 1

    def overlapping_cidrs(self, cidr: str, limit: int = 20) -> list[str]:
        net = _parse_network(cidr)
        if net is None:
            return []
        index = self.v4 if net.version == 4 else self.v6
        out: list[str] = []
        for s, e in index.overlapping_ranges(int(net.network_address), int(net.broadcast_address), limit):
            a = ipaddress.ip_address(s)
            b = ipaddress.ip_address(e)
            try:
                nets = list(ipaddress.summarize_address_range(a, b))
                out.extend(str(n) for n in nets[:3])
            except ValueError:
                out.append(f"{a}-{b}")
        return out[:limit]

    @property
    def ipv4_count(self) -> int:
        return self.v4.address_count()


def ipv4_size(cidr: str) -> int:
    net = _parse_network(cidr)
    if net is None or net.version != 4:
        return 0
    return net.num_addresses


def sample_ips(cidr: str, count: int = 6) -> list[str]:
    """Равномерная выборка адресов внутри префикса (без network/broadcast для v4)."""
    net = _parse_network(cidr)
    if net is None:
        return []
    start, end = int(net.network_address), int(net.broadcast_address)
    if net.version == 4 and end - start >= 4:
        start += 1
        end -= 1
    span = end - start
    if span <= 0:
        return [str(ipaddress.ip_address(start))]
    count = max(1, min(count, span + 1))
    picks = sorted({start + (span * i) // (count + 1) + 1 for i in range(count)})
    return [str(ipaddress.ip_address(min(p, end))) for p in picks]
