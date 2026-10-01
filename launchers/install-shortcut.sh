#!/usr/bin/env bash
# Создаёт ярлык Shadow Scout: .desktop в меню приложений и на рабочем столе (Linux) или .command на рабочем столе (macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chmod +x "$ROOT/launchers/shadow-scout.sh"

if [ "$(uname)" = "Darwin" ]; then
  TARGET="$HOME/Desktop/Shadow Scout.command"
  printf '#!/bin/bash\ncd "%s"\nexec "%s/launchers/shadow-scout.sh"\n' "$ROOT" "$ROOT" > "$TARGET"
  chmod +x "$TARGET"
  echo "Ярлык создан: $TARGET (двойной клик запускает приложение в Terminal)"
  exit 0
fi

DESKTOP_FILE="shadow-scout.desktop"
CONTENT="[Desktop Entry]
Type=Application
Name=Shadow Scout
Comment=Поиск VPS под VPN вне радара РКН
Exec=$ROOT/launchers/shadow-scout.sh
Path=$ROOT
Icon=utilities-terminal
Terminal=true
Categories=Network;Utility;
"
mkdir -p "$HOME/.local/share/applications"
printf '%s' "$CONTENT" > "$HOME/.local/share/applications/$DESKTOP_FILE"
if [ -d "$HOME/Desktop" ]; then
  printf '%s' "$CONTENT" > "$HOME/Desktop/$DESKTOP_FILE"
  chmod +x "$HOME/Desktop/$DESKTOP_FILE"
  command -v gio >/dev/null 2>&1 && gio set "$HOME/Desktop/$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "Ярлык создан: ~/.local/share/applications/$DESKTOP_FILE (и на рабочем столе, если он есть)"
