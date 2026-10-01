"""Простой дисковый кеш JSON-ответов и файлов с TTL."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from shadow_scout.paths import cache_dir


class DiskCache:
    def __init__(self, namespace: str, root: Path | None = None) -> None:
        self.root = (root or cache_dir()) / namespace
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:24]
        return self.root / f"{digest}.json"

    def get(self, key: str, ttl_seconds: float | None) -> Any | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if ttl_seconds is not None and time.time() - payload.get("ts", 0) > ttl_seconds:
            return None
        return payload.get("value")

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"ts": time.time(), "key": key, "value": value}, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    def age_seconds(self, key: str) -> float | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return time.time() - payload.get("ts", 0)
        except (OSError, ValueError):
            return None

    def clear(self) -> int:
        count = 0
        for file in self.root.glob("*.json"):
            try:
                file.unlink()
                count += 1
            except OSError:
                pass
        return count


class FileCache:
    """Кеш больших текстовых файлов (списки блокировок, таблицы ASN)."""

    def __init__(self, namespace: str = "files", root: Path | None = None) -> None:
        self.root = (root or cache_dir()) / namespace
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, key: str) -> Path:
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        safe = "".join(ch if ch.isalnum() else "_" for ch in key)[-40:]
        return self.root / f"{safe}_{digest}.txt"

    def get(self, key: str, ttl_seconds: float | None) -> str | None:
        path = self.path_for(key)
        if not path.exists():
            return None
        if ttl_seconds is not None and time.time() - path.stat().st_mtime > ttl_seconds:
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def get_stale(self, key: str) -> str | None:
        return self.get(key, None)

    def set(self, key: str, text: str) -> Path:
        path = self.path_for(key)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return path

    def age_seconds(self, key: str) -> float | None:
        path = self.path_for(key)
        if not path.exists():
            return None
        return time.time() - path.stat().st_mtime

    def clear(self) -> int:
        count = 0
        for file in self.root.glob("*.txt"):
            try:
                file.unlink()
                count += 1
            except OSError:
                pass
        return count
