@echo off
setlocal
title Shadow Scout
chcp 65001 >nul
cd /d "%~dp0\.."

set "PYLAUNCH="
where py >nul 2>nul && set "PYLAUNCH=py -3"
if not defined PYLAUNCH where python >nul 2>nul && set "PYLAUNCH=python"
if not defined PYLAUNCH (
  echo [Shadow Scout] Python 3.10+ not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [Shadow Scout] First run: creating virtual environment and installing dependencies...
  %PYLAUNCH% -m venv .venv || (echo [Shadow Scout] Failed to create .venv & pause & exit /b 1)
  ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
  ".venv\Scripts\python.exe" -m pip install -e . || (echo [Shadow Scout] Dependency installation failed & pause & exit /b 1)
)

".venv\Scripts\python.exe" -m shadow_scout %*
set "RC=%errorlevel%"
if not "%RC%"=="0" (
  echo.
  echo [Shadow Scout] Exited with code %RC%.
  pause
)
endlocal
