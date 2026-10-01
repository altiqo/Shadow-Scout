#!/usr/bin/env bash
# Запуск Shadow Scout (Linux/macOS): создаёт venv при первом запуске и стартует приложение.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "[Shadow Scout] Python 3.10+ не найден. Установите python3 и повторите." >&2
  exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
  echo "[Shadow Scout] Первый запуск: создаю окружение и ставлю зависимости..."
  "$PY" -m venv .venv
  ".venv/bin/python" -m pip install --upgrade pip >/dev/null
  ".venv/bin/python" -m pip install -e .
fi

exec ".venv/bin/python" -m shadow_scout "$@"
